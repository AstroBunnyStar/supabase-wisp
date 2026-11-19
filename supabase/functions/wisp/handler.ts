/**
 * Supabase Edge Function handler for the Wisp relay.
 *
 * Responsibilities:
 *  - answer plain HTTP with a small status document (handy for health checks)
 *  - reject the upgrade when a token is configured and missing
 *  - detect Wisp v2 (Sec-WebSocket-Protocol present) vs v1
 *  - keep the Edge Function worker alive for the life of the socket
 */

import { WispSession } from "./wisp.ts";
import type { Logger, RelayFactory, WispSocketLike } from "./wisp.ts";
import { createDenoRelay } from "./deno_relay.ts";
import { createHostFilter, splitList } from "./policy.ts";

export const SERVER_NAME = "supabase-wisp";
export const SERVER_VERSION = "1.0.0";

export interface HandlerConfig {
  relay: RelayFactory;
  bufferSize: number;
  maxStreams: number;
  allowUdp: boolean;
  motd?: string;
  token?: string;
  /** Close the socket after this many seconds. 0 = leave it to the platform. */
  maxSeconds: number;
  /** Packets per second per connection. 0 disables the limiter. */
  rateLimit: number;
  allowPrivate: boolean;
  blockedHosts: string[];
  allowedHosts: string[];
  /** Only log warnings/errors (Supabase bills nothing for logs, but keep it tidy). */
  quiet: boolean;
}

type EdgeRuntimeLike = { waitUntil(promise: Promise<unknown>): void };

function makeLogger(quiet: boolean): Logger {
  return (level, message, fields) => {
    if (quiet && level !== "warn" && level !== "error") return;
    const line = fields ? `${message} ${JSON.stringify(fields)}` : message;
    const prefix = `[wisp] ${level}`;
    if (level === "error") console.error(prefix, line);
    else if (level === "warn") console.warn(prefix, line);
    else console.log(prefix, line);
  };
}

function statusResponse(config: HandlerConfig): Response {
  const body = {
    name: SERVER_NAME,
    version: SERVER_VERSION,
    protocols: ["wisp/2.1", "wisp/1"],
    transports: config.allowUdp && config.relay.supportsUdp
      ? ["tcp", "udp"]
      : ["tcp"],
    endpoint:
      "wss://<project-ref>.supabase.co/functions/v1/wisp/ (send Sec-WebSocket-Protocol: wisp)",
    limits: {
      streamsPerConnection: config.maxStreams,
      bufferPackets: config.bufferSize,
      packetsPerSecond: config.rateLimit,
      maxConnectionSeconds: config.maxSeconds,
    },
    auth: config.token ? "token required (?token=...)" : "open",
  };
  return new Response(JSON.stringify(body, null, 2), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "cache-control": "no-store",
    },
  });
}

export function createHandler(
  config: HandlerConfig,
): (request: Request) => Promise<Response> {
  const logger = makeLogger(config.quiet);
  const isHostAllowed = createHostFilter({
    blocked: config.blockedHosts,
    allowed: config.allowedHosts,
    allowPrivate: config.allowPrivate,
  });

  return async function handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const upgrade = (request.headers.get("upgrade") ?? "").toLowerCase();

    if (upgrade !== "websocket") {
      return statusResponse(config);
    }

    if (config.token && url.searchParams.get("token") !== config.token) {
      return new Response("401 Unauthorized: missing or invalid ?token=\n", {
        status: 401,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    // The presence of Sec-WebSocket-Protocol selects Wisp v2; without it the
    // connection is treated as v1 (see the protocol's HTTP behavior section).
    const offered = (request.headers.get("sec-websocket-protocol") ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
    const protocol = offered[0] ?? "";
    const v2 = protocol.length > 0;

    const options: { protocol?: string; idleTimeout?: number } = {
      idleTimeout: 0,
    };
    if (v2) options.protocol = protocol;

    const { socket, response } = Deno.upgradeWebSocket(request, options);

    const session = new WispSession(socket as unknown as WispSocketLike, {
      relay: config.relay,
      v2,
      bufferSize: config.bufferSize,
      maxStreams: config.maxStreams,
      motd: config.motd,
      allowUdp: config.allowUdp,
      rateLimit: config.rateLimit,
      hostFilter: isHostAllowed,
      logger,
    });

    const closed = new Promise<void>((resolve) => {
      session.onClosed = resolve;
    });

    socket.addEventListener("open", () => session.start());
    socket.addEventListener("message", (event) => session.receive(event.data));
    socket.addEventListener("close", () => session.dispose());
    socket.addEventListener("error", () => session.dispose());

    if (config.maxSeconds > 0) {
      const timer = setTimeout(() => {
        logger("info", "closing connection at configured limit", {
          seconds: config.maxSeconds,
        });
        try {
          socket.close(1000, "max connection time");
        } catch { /* already closed */ }
        session.dispose();
      }, config.maxSeconds * 1000);
      void closed.then(() => clearTimeout(timer));
    }

    // Supabase treats the request as finished once the upgrade response is
    // returned; without a pending waitUntil the worker can be retired early.
    const edgeRuntime = (globalThis as { EdgeRuntime?: EdgeRuntimeLike })
      .EdgeRuntime;
    if (edgeRuntime?.waitUntil) {
      try {
        edgeRuntime.waitUntil(closed);
      } catch {
        // Older runtimes: the socket still works, it may just be reaped early.
      }
    }

    // Send INFO right away when the socket is already open.
    queueMicrotask(() => session.start());

    return response;
  };
}

export function loadConfigFromEnv(): HandlerConfig {
  const env = (name: string): string | undefined => {
    const value = Deno.env.get(name);
    return value && value.length > 0 ? value : undefined;
  };
  const number = (
    name: string,
    fallback: number,
    min: number,
    max: number,
  ): number => {
    const raw = env(name);
    if (!raw) return fallback;
    const parsed = Number(raw);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(min, Math.trunc(parsed)));
  };
  const bool = (name: string, fallback: boolean): boolean => {
    const raw = env(name)?.toLowerCase();
    if (!raw) return fallback;
    return ["1", "true", "yes", "on"].includes(raw);
  };

  const allowUdp = bool("WISP_UDP", true);

  return {
    relay: createDenoRelay({
      udp: allowUdp,
      connectTimeoutMs: number("WISP_CONNECT_TIMEOUT_MS", 10000, 1000, 30000),
    }),
    bufferSize: number("WISP_BUFFER_SIZE", 64, 4, 1024),
    maxStreams: number("WISP_MAX_STREAMS", 16, 1, 256),
    allowUdp,
    motd: env("WISP_MOTD"),
    token: env("WISP_TOKEN"),
    maxSeconds: number("WISP_MAX_SECONDS", 0, 0, 3600),
    rateLimit: number("WISP_RATE_LIMIT", 2000, 0, 100000),
    allowPrivate: bool("WISP_ALLOW_PRIVATE", false),
    blockedHosts: splitList(env("WISP_BLOCKED_HOSTS")),
    allowedHosts: splitList(env("WISP_ALLOWED_HOSTS")),
    quiet: bool("WISP_QUIET", true),
  };
}
