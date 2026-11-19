/**
 * Wisp protocol core (v1 + v2), runtime agnostic.
 *
 * Spec: https://github.com/MercuryWorkshop/wisp-protocol
 *
 * One WebSocket multiplexes many TCP/UDP streams. This module owns packet
 * framing, the v2 INFO handshake, CONTINUE flow control credits and close
 * codes. Real sockets come from a RelayFactory, so the same core runs on Deno
 * (Supabase Edge Functions) and inside tests.
 *
 * Packet layout (all little-endian):
 *   uint8   packet type
 *   uint32  stream id   (0 is reserved for the handshake)
 *   bytes   payload
 */

export const PACKET = {
  CONNECT: 0x01,
  DATA: 0x02,
  CONTINUE: 0x03,
  CLOSE: 0x04,
  INFO: 0x05,
} as const;

export const CLOSE_REASON = {
  /** Unspecified. */
  UNSPECIFIED: 0x01,
  /** Voluntary stream closure (either side reset it). */
  VOLUNTARY: 0x02,
  /** Network error on the proxied socket. */
  NETWORK_ERROR: 0x03,
  /** Incompatible Wisp versions / extensions during the handshake. */
  INCOMPATIBLE: 0x04,
  /** Invalid CONNECT information. */
  INVALID_INFO: 0x41,
  /** Destination unreachable (DNS failure). */
  UNREACHABLE: 0x42,
  /** Destination timed out. */
  TIMEOUT: 0x43,
  /** Destination refused the connection. */
  REFUSED: 0x44,
  /** Proxy blocked the destination (policy). */
  BLOCKED: 0x48,
  /** Proxy throttled the connection. */
  THROTTLED: 0x49,
  /** Extension: authentication failed. */
  AUTH_FAILED: 0xc0,
} as const;

export const EXTENSION = {
  UDP: 0x01,
  PASSWORD: 0x02,
  KEY: 0x03,
  MOTD: 0x04,
  STREAM_CONFIRMATION: 0x05,
} as const;

export const WISP_MAJOR = 2;
export const WISP_MINOR = 1;

const HEADER_SIZE = 5;
const MAX_HOST_LENGTH = 253;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export type StreamKind = "tcp" | "udp";

/** The subset of the WebSocket API the core needs. */
export interface WispSocketLike {
  readonly readyState?: number;
  send(data: Uint8Array): void;
  close(code?: number, reason?: string): void;
}

export interface RelayHandlers {
  /** Bytes that arrived from the proxied destination. */
  onData(chunk: Uint8Array): void;
  /** Destination closed; `reason` is a Wisp close reason. */
  onClose(reason: number): void;
}

export interface RelayStream {
  /** Resolves once the bytes are handed to the operating system. */
  write(chunk: Uint8Array): Promise<void>;
  close(): void;
}

export interface RelayFactory {
  supportsUdp: boolean;
  connect(
    kind: StreamKind,
    host: string,
    port: number,
    handlers: RelayHandlers,
  ): Promise<RelayStream>;
}

export type LogLevel = "debug" | "info" | "warn" | "error";
export type Logger = (
  level: LogLevel,
  message: string,
  fields?: Record<string, unknown>,
) => void;

export interface WispSessionDeps {
  relay: RelayFactory;
  /** True when the client offered `Sec-WebSocket-Protocol` (Wisp v2). */
  v2: boolean;
  /** DATA packets the server buffers per TCP stream (CONTINUE credit). */
  bufferSize?: number;
  maxStreams?: number;
  motd?: string;
  allowUdp?: boolean;
  /** Packets per second, per connection. 0 disables the limiter. */
  rateLimit?: number;
  /** Return false to refuse a destination host. */
  hostFilter?: (host: string) => boolean;
  logger?: Logger;
}

interface StreamState {
  id: number;
  kind: StreamKind;
  relay: RelayStream | null;
  /** DATA received before the destination socket finished connecting. */
  queue: Uint8Array[];
  /** DATA packets received but not yet written to the destination socket. */
  pending: number;
  /** Last CONTINUE credit value announced to the client. */
  credit: number;
  closed: boolean;
}

const noopLogger: Logger = () => {};

/** Serialize one Wisp packet. */
export function encodePacket(
  type: number,
  streamId: number,
  payload: Uint8Array = new Uint8Array(0),
): Uint8Array {
  const packet = new Uint8Array(HEADER_SIZE + payload.length);
  const view = new DataView(packet.buffer);
  view.setUint8(0, type);
  view.setUint32(1, streamId, true);
  packet.set(payload, HEADER_SIZE);
  return packet;
}

export function decodePacketHeader(bytes: Uint8Array): {
  type: number;
  streamId: number;
  payload: Uint8Array;
} | null {
  if (bytes.length < HEADER_SIZE) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    type: view.getUint8(0),
    streamId: view.getUint32(1, true),
    payload: bytes.subarray(HEADER_SIZE),
  };
}

export function encodeExtension(id: number, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(5 + payload.length);
  out[0] = id;
  new DataView(out.buffer).setUint32(1, payload.length, true);
  out.set(payload, 5);
  return out;
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function closeReasonForConnectError(error: unknown): number {
  const name = typeof error === "object" && error !== null && "name" in error
    ? String((error as { name: unknown }).name)
    : "";
  const message = error instanceof Error ? error.message : String(error);
  const haystack = `${name} ${message}`.toLowerCase();
  if (haystack.includes("refused")) return CLOSE_REASON.REFUSED;
  if (haystack.includes("timed out") || haystack.includes("timeout")) {
    return CLOSE_REASON.TIMEOUT;
  }
  if (
    haystack.includes("notfound") || haystack.includes("not found") ||
    haystack.includes("dns") || haystack.includes("resolve") ||
    haystack.includes("lookup") || haystack.includes("no such host") ||
    haystack.includes("getaddrinfo") || haystack.includes("name or service")
  ) {
    return CLOSE_REASON.UNREACHABLE;
  }
  if (
    haystack.includes("permission") || haystack.includes("invalid") ||
    haystack.includes("blocked")
  ) {
    return CLOSE_REASON.INVALID_INFO;
  }
  return CLOSE_REASON.UNREACHABLE;
}

function isValidHostname(host: string): boolean {
  if (host.length === 0 || host.length > MAX_HOST_LENGTH) return false;
  // Control characters, spaces and whitespace are never valid in a host.
  return !/[\u0000-\u0020\u007f]/.test(host);
}

export class WispSession {
  private readonly ws: WispSocketLike;
  private readonly relay: RelayFactory;
  private readonly v2: boolean;
  private readonly bufferSize: number;
  private readonly maxStreams: number;
  private readonly motd: string | undefined;
  private readonly allowUdp: boolean;
  private readonly rateLimit: number;
  private readonly hostFilter: (host: string) => boolean;
  private readonly logger: Logger;

  private readonly streams = new Map<number, StreamState>();
  private started = false;
  private ready = false;
  private disposed = false;
  private clientUdp = false;
  private confirmStreams = false;
  private tokens: number;
  private lastRefill: number;

  /** Called once when the session is torn down. */
  onClosed?: () => void;

  constructor(ws: WispSocketLike, deps: WispSessionDeps) {
    this.ws = ws;
    this.relay = deps.relay;
    this.v2 = deps.v2;
    this.bufferSize = Math.max(4, deps.bufferSize ?? 64);
    this.maxStreams = Math.max(1, deps.maxStreams ?? 16);
    this.motd = deps.motd;
    this.allowUdp = (deps.allowUdp ?? true) && this.relay.supportsUdp;
    this.rateLimit = Math.max(0, deps.rateLimit ?? 0);
    this.hostFilter = deps.hostFilter ?? (() => true);
    this.logger = deps.logger ?? noopLogger;
    this.tokens = this.rateLimit;
    this.lastRefill = Date.now();
  }

  get udpEnabled(): boolean {
    return this.allowUdp;
  }

  /** Send the server INFO packet, or the v1 CONTINUE, exactly once. */
  start(): void {
    if (this.started || this.disposed) return;
    if (this.ws.readyState !== undefined && this.ws.readyState !== 1) return;
    this.started = true;
    if (!this.v2) {
      // No Sec-WebSocket-Protocol header: behave like a Wisp v1 server.
      this.ready = true;
      this.sendContinue(0, this.bufferSize);
      return;
    }
    this.sendInfo();
  }

  receive(data: unknown): void {
    if (this.disposed) return;
    if (data instanceof ArrayBuffer) {
      this.handleBytes(new Uint8Array(data));
      return;
    }
    if (ArrayBuffer.isView(data)) {
      const view = data as ArrayBufferView;
      this.handleBytes(
        new Uint8Array(view.buffer, view.byteOffset, view.byteLength),
      );
      return;
    }
    if (typeof Blob !== "undefined" && data instanceof Blob) {
      void data.arrayBuffer().then((buffer) => {
        if (!this.disposed) this.handleBytes(new Uint8Array(buffer));
      }).catch(() => {});
    }
    // Text frames are not part of Wisp; ignore them.
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    for (const state of this.streams.values()) {
      state.closed = true;
      state.relay?.close();
    }
    this.streams.clear();
    this.onClosed?.();
  }

  private handleBytes(bytes: Uint8Array): void {
    const packet = decodePacketHeader(bytes);
    if (!packet) {
      this.logger("warn", "malformed packet (too short)");
      return;
    }
    if (!this.allowPacket()) {
      this.sendClosePacket(0, CLOSE_REASON.THROTTLED);
      this.logger("warn", "packet rate limit exceeded");
      this.dispose();
      try {
        this.ws.close(1008, "rate limit exceeded");
      } catch { /* already closed */ }
      return;
    }

    const { type, streamId, payload } = packet;

    if (streamId === 0) {
      if (type === PACKET.INFO) {
        this.handleInfo(payload);
        return;
      }
      if (type === PACKET.CLOSE) {
        // Client rejected the handshake.
        this.dispose();
        try {
          this.ws.close(1000, "client closed handshake");
        } catch { /* already closed */ }
        return;
      }
      this.sendClosePacket(0, CLOSE_REASON.INVALID_INFO);
      this.dispose();
      return;
    }

    if (!this.ready) {
      // Nothing may be multiplexed before the handshake completes.
      this.sendClosePacket(streamId, CLOSE_REASON.INVALID_INFO);
      return;
    }

    switch (type) {
      case PACKET.CONNECT:
        this.handleConnect(streamId, payload);
        break;
      case PACKET.DATA:
        this.handleData(streamId, payload);
        break;
      case PACKET.CONTINUE:
        // Servers do not consume client CONTINUE credits; ignore.
        break;
      case PACKET.CLOSE: {
        const reason = payload.length > 0 ? payload[0] : CLOSE_REASON.UNSPECIFIED;
        this.endStream(streamId, reason, false);
        break;
      }
      default:
        this.logger("warn", "unknown packet type", { type });
    }
  }

  private handleInfo(payload: Uint8Array): void {
    if (this.ready) return; // duplicate INFO
    if (payload.length < 2) {
      this.failHandshake(CLOSE_REASON.INVALID_INFO, "malformed INFO");
      return;
    }
    const major = payload[0];
    if (major !== WISP_MAJOR) {
      this.failHandshake(CLOSE_REASON.INCOMPATIBLE, `unsupported Wisp version ${major}`);
      return;
    }

    let offset = 2;
    const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    while (offset + 5 <= payload.length) {
      const id = payload[offset];
      const length = view.getUint32(offset + 1, true);
      offset += 5;
      if (offset + length > payload.length) break;
      if (id === EXTENSION.UDP) this.clientUdp = true;
      if (id === EXTENSION.STREAM_CONFIRMATION) this.confirmStreams = true;
      offset += length;
    }

    this.ready = true;
    this.sendContinue(0, this.bufferSize);
    this.logger("info", "wisp v2 handshake", {
      udp: this.clientUdp,
      streamConfirmation: this.confirmStreams,
    });
  }

  private handleConnect(streamId: number, payload: Uint8Array): void {
    if (this.streams.has(streamId)) {
      this.sendClosePacket(streamId, CLOSE_REASON.INVALID_INFO);
      return;
    }
    if (this.streams.size >= this.maxStreams) {
      this.sendClosePacket(streamId, CLOSE_REASON.THROTTLED);
      return;
    }
    if (payload.length < 3) {
      this.sendClosePacket(streamId, CLOSE_REASON.INVALID_INFO);
      return;
    }

    const kindByte = payload[0];
    const kind: StreamKind | null = kindByte === 0x01
      ? "tcp"
      : kindByte === 0x02
      ? "udp"
      : null;
    if (!kind) {
      this.sendClosePacket(streamId, CLOSE_REASON.INVALID_INFO);
      return;
    }

    const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    const port = view.getUint16(1, true);
    const host = textDecoder.decode(payload.subarray(3));

    if (port === 0 || !isValidHostname(host)) {
      this.sendClosePacket(streamId, CLOSE_REASON.INVALID_INFO);
      return;
    }
    if (kind === "udp" && (!this.allowUdp || (this.v2 && !this.clientUdp))) {
      this.sendClosePacket(streamId, CLOSE_REASON.INVALID_INFO);
      return;
    }
    if (!this.hostFilter(host)) {
      this.logger("warn", "blocked destination", { host, port });
      this.sendClosePacket(streamId, CLOSE_REASON.BLOCKED);
      return;
    }

    const state: StreamState = {
      id: streamId,
      kind,
      relay: null,
      queue: [],
      pending: 0,
      credit: 0,
      closed: false,
    };
    this.streams.set(streamId, state);
    this.logger("info", "stream opening", { streamId, kind, host, port });

    this.relay.connect(kind, host, port, {
      onData: (chunk) => this.fromRelay(streamId, chunk),
      onClose: (reason) => this.endStream(streamId, reason, true),
    }).then((relay) => {
      if (state.closed) {
        relay.close();
        return;
      }
      state.relay = relay;
      if (kind === "tcp") {
        // Grants the client its initial send credit (and confirms the open).
        state.credit = this.bufferSize;
        this.sendContinue(streamId, this.bufferSize);
      }
      const queued = state.queue;
      state.queue = [];
      for (const chunk of queued) this.writeToRelay(state, chunk);
    }).catch((error) => {
      const reason = closeReasonForConnectError(error);
      this.logger("warn", "stream failed", {
        streamId,
        host,
        port,
        reason,
        error: error instanceof Error ? error.message : String(error),
      });
      this.endStream(streamId, reason, true);
    });
  }

  private handleData(streamId: number, payload: Uint8Array): void {
    const state = this.streams.get(streamId);
    if (!state || state.closed || payload.length === 0) return;

    if (state.kind === "udp") {
      const relay = state.relay;
      if (relay) {
        relay.write(payload).catch(() =>
          this.endStream(streamId, CLOSE_REASON.NETWORK_ERROR, true)
        );
      }
      return;
    }

    if (!state.relay) {
      // The destination socket is still connecting; buffer like the spec asks.
      if (state.queue.length < this.bufferSize) state.queue.push(payload);
      return;
    }
    this.writeToRelay(state, payload);
  }

  private writeToRelay(state: StreamState, chunk: Uint8Array): void {
    const relay = state.relay;
    if (!relay || state.closed) return;
    state.pending += 1;
    relay.write(chunk).then(() => {
      state.pending -= 1;
      if (state.closed || state.kind === "udp") return;
      // Hand credit back as the destination drains, so the client never stalls.
      const remaining = this.bufferSize - state.pending;
      if (remaining > state.credit) {
        state.credit = remaining;
        this.sendContinue(state.id, remaining);
      }
    }).catch(() => {
      this.endStream(state.id, CLOSE_REASON.NETWORK_ERROR, true);
    });
  }

  private fromRelay(streamId: number, chunk: Uint8Array): void {
    const state = this.streams.get(streamId);
    if (!state || state.closed) return;
    if (state.kind === "udp") {
      // UDP has no flow control: send immediately.
      this.send(PACKET.DATA, streamId, chunk);
      return;
    }
    this.send(PACKET.DATA, streamId, chunk);
  }

  private endStream(streamId: number, reason: number, notifyPeer: boolean): void {
    const state = this.streams.get(streamId);
    if (!state) return;
    state.closed = true;
    state.relay?.close();
    this.streams.delete(streamId);
    if (notifyPeer) this.sendClosePacket(streamId, reason);
    this.logger("info", "stream closed", { streamId, reason });
  }

  private failHandshake(reason: number, message: string): void {
    this.sendClosePacket(0, reason);
    this.logger("warn", "handshake rejected", { message });
    this.dispose();
    try {
      this.ws.close(1002, "wisp handshake rejected");
    } catch { /* already closed */ }
  }

  private sendInfo(): void {
    const extensions: Uint8Array[] = [];
    if (this.allowUdp) {
      extensions.push(encodeExtension(EXTENSION.UDP, new Uint8Array(0)));
    }
    if (this.motd) {
      extensions.push(encodeExtension(EXTENSION.MOTD, textEncoder.encode(this.motd)));
    }
    extensions.push(encodeExtension(EXTENSION.STREAM_CONFIRMATION, new Uint8Array(0)));
    this.send(
      PACKET.INFO,
      0,
      concatBytes([Uint8Array.of(WISP_MAJOR, WISP_MINOR), ...extensions]),
    );
  }

  private sendContinue(streamId: number, bufferRemaining: number): void {
    const payload = new Uint8Array(4);
    new DataView(payload.buffer).setUint32(0, bufferRemaining, true);
    this.send(PACKET.CONTINUE, streamId, payload);
  }

  private sendClosePacket(streamId: number, reason: number): void {
    this.send(PACKET.CLOSE, streamId, Uint8Array.of(reason));
  }

  private send(type: number, streamId: number, payload: Uint8Array): void {
    if (this.disposed) return;
    if (this.ws.readyState !== undefined && this.ws.readyState !== 1) return;
    try {
      this.ws.send(encodePacket(type, streamId, payload));
    } catch (error) {
      this.logger("warn", "websocket send failed", {
        error: error instanceof Error ? error.message : String(error),
      });
      this.dispose();
    }
  }

  private allowPacket(): boolean {
    if (this.rateLimit === 0) return true;
    const now = Date.now();
    const elapsedSeconds = (now - this.lastRefill) / 1000;
    this.lastRefill = now;
    this.tokens = Math.min(
      this.rateLimit,
      this.tokens + elapsedSeconds * this.rateLimit,
    );
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }
}
