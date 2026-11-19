/**
 * Deno socket adapter: turns Deno.connect() TCP/UDP sockets into RelayStreams.
 *
 * Supabase Edge Functions run on Deno with native TCP support, so this is the
 * only runtime-specific piece of the server. Only ports 25 and 587 are blocked
 * by the platform; Minecraft's 25565 and ordinary web ports work.
 */

import { CLOSE_REASON } from "./wisp.ts";
import type {
  RelayFactory,
  RelayHandlers,
  RelayStream,
  StreamKind,
} from "./wisp.ts";

const READ_CHUNK_SIZE = 32 * 1024;
const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;

export interface DenoRelayOptions {
  /** Offer UDP streams (default true). */
  udp?: boolean;
  connectTimeoutMs?: number;
}

class ConnectTimeoutError extends Error {
  constructor(message = "connect timed out") {
    super(message);
    this.name = "TimeoutError";
  }
}

function closeQuietly(conn: { close(): void }): void {
  try {
    conn.close();
  } catch {
    // Already closed.
  }
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  if (timeoutMs <= 0) return promise;
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new ConnectTimeoutError()), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

export function createDenoRelay(options: DenoRelayOptions = {}): RelayFactory {
  const udpEnabled = options.udp ?? true;
  const timeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;

  return {
    supportsUdp: udpEnabled,
    connect(
      kind: StreamKind,
      host: string,
      port: number,
      handlers: RelayHandlers,
    ): Promise<RelayStream> {
      if (kind === "udp") {
        if (!udpEnabled) return Promise.reject(new Error("UDP is disabled"));
        return connectDatagram(host, port, handlers, timeoutMs);
      }
      return connectStream(host, port, handlers, timeoutMs);
    },
  };
}

async function connectStream(
  host: string,
  port: number,
  handlers: RelayHandlers,
  timeoutMs: number,
): Promise<RelayStream> {
  const connecting = Deno.connect({
    hostname: host,
    port,
    transport: "tcp",
  }) as Promise<Deno.Conn>;

  let conn: Deno.Conn;
  try {
    conn = await withTimeout(connecting, timeoutMs);
  } catch (error) {
    // The connect may still succeed after the timeout; make sure it is closed.
    connecting.then((late) => closeQuietly(late)).catch(() => {});
    throw error;
  }

  let closed = false;
  let chain: Promise<void> = Promise.resolve();

  // Pump destination -> client for the lifetime of the socket.
  (async () => {
    const buffer = new Uint8Array(READ_CHUNK_SIZE);
    try {
      while (!closed) {
        const read = await conn.read(buffer);
        if (read === null) break;
        if (read > 0) handlers.onData(buffer.slice(0, read));
      }
      if (!closed) handlers.onClose(CLOSE_REASON.VOLUNTARY);
    } catch {
      if (!closed) handlers.onClose(CLOSE_REASON.NETWORK_ERROR);
    }
  })();

  return {
    write(chunk: Uint8Array): Promise<void> {
      if (closed) return Promise.resolve();
      // Serialize writes so bytes from different DATA packets never interleave.
      const operation = chain.then(async () => {
        if (closed) return;
        let offset = 0;
        while (offset < chunk.length) {
          offset += await conn.write(chunk.subarray(offset));
        }
      });
      chain = operation.catch(() => {});
      return operation;
    },
    close(): void {
      if (closed) return;
      closed = true;
      closeQuietly(conn);
    },
  };
}

async function connectDatagram(
  host: string,
  port: number,
  handlers: RelayHandlers,
  timeoutMs: number,
): Promise<RelayStream> {
  // Connected UDP sockets are not part of every Deno release's connect()
  // typings; cast so the code builds, and let a runtime that lacks UDP reject
  // here (the session turns that into a CLOSE packet for the stream).
  const connectUdp = Deno.connect as unknown as (
    options: { hostname: string; port: number; transport: "udp" },
  ) => Promise<Deno.Conn>;
  const connecting = connectUdp({ hostname: host, port, transport: "udp" });

  let conn: Deno.Conn;
  try {
    conn = await withTimeout(connecting, timeoutMs);
  } catch (error) {
    connecting.then((late) => closeQuietly(late)).catch(() => {});
    throw error;
  }

  let closed = false;
  let chain: Promise<void> = Promise.resolve();

  // One datagram in, one DATA packet out.
  (async () => {
    const buffer = new Uint8Array(READ_CHUNK_SIZE);
    try {
      while (!closed) {
        const read = await conn.read(buffer);
        if (read === null) break;
        if (read > 0) handlers.onData(buffer.slice(0, read));
      }
    } catch {
      // Connected UDP sockets surface ICMP errors here; just end the stream.
    }
    if (!closed) handlers.onClose(CLOSE_REASON.VOLUNTARY);
  })();

  return {
    write(chunk: Uint8Array): Promise<void> {
      if (closed) return Promise.resolve();
      const operation = chain.then(async () => {
        if (closed) return;
        await conn.write(chunk);
      });
      chain = operation.catch(() => {});
      return operation;
    },
    close(): void {
      if (closed) return;
      closed = true;
      closeQuietly(conn);
    },
  };
}
