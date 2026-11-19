/**
 * End-to-end tests for the Wisp relay.
 *
 * Each test starts the real handler on a loopback port, connects with the real
 * Deno WebSocket client, and relays to a real TCP echo server. No mocks of the
 * protocol or of the socket layer.
 *
 * Run: deno test -A tests/
 */

import { CLOSE_REASON, PACKET, encodePacket } from "../supabase/functions/wisp/wisp.ts";
import { createHandler, type HandlerConfig } from "../supabase/functions/wisp/handler.ts";
import { createDenoRelay } from "../supabase/functions/wisp/deno_relay.ts";

const HOST = "127.0.0.1";

function assertEquals<T>(actual: T, expected: T, message = "value"): void {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${String(expected)}, got ${String(actual)}`);
  }
}

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`assertion failed: ${message}`);
}

function assertBytes(actual: Uint8Array, expected: string, message = "bytes"): void {
  const actualText = new TextDecoder().decode(actual);
  if (actualText !== expected) {
    throw new Error(`${message}: expected "${expected}", got "${actualText}"`);
  }
}

function testConfig(overrides: Partial<HandlerConfig> = {}): HandlerConfig {
  return {
    relay: createDenoRelay(),
    bufferSize: 4,
    maxStreams: 2,
    allowUdp: false,
    maxSeconds: 0,
    rateLimit: 0,
    allowPrivate: true,
    blockedHosts: [],
    allowedHosts: [],
    quiet: true,
    ...overrides,
  };
}

interface RunningServer {
  port: number;
  url: (path?: string) => string;
  stop: () => Promise<void>;
}

async function startServer(config: HandlerConfig): Promise<RunningServer> {
  const server = Deno.serve(
    { hostname: HOST, port: 0, onListen: () => {} },
    createHandler(config),
  );
  const port = (server.addr as Deno.NetAddr).port;
  return {
    port,
    url: (path = "/functions/v1/wisp/") => `ws://${HOST}:${port}${path}`,
    stop: () => server.shutdown(),
  };
}

interface Packet {
  type: number;
  streamId: number;
  payload: Uint8Array;
}

function decode(bytes: Uint8Array): Packet {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    type: view.getUint8(0),
    streamId: view.getUint32(1, true),
    payload: bytes.subarray(5),
  };
}

class TestClient {
  private readonly queue: Packet[] = [];
  private readonly waiters: Array<(packet: Packet) => void> = [];

  private constructor(readonly ws: WebSocket) {
    ws.binaryType = "arraybuffer";
    ws.addEventListener("message", (event) => {
      const data = event.data;
      if (!(data instanceof ArrayBuffer)) return;
      const packet = decode(new Uint8Array(data));
      const waiter = this.waiters.shift();
      if (waiter) waiter(packet);
      else this.queue.push(packet);
    });
  }

  static async open(url: string, protocols?: string[]): Promise<TestClient> {
    const ws = protocols ? new WebSocket(url, protocols) : new WebSocket(url);
    const client = new TestClient(ws);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("websocket open timed out")), 5000);
      ws.addEventListener("open", () => {
        clearTimeout(timer);
        resolve();
      });
      ws.addEventListener("error", () => {
        clearTimeout(timer);
        reject(new Error("websocket errored before opening"));
      });
    });
    return client;
  }

  next(timeoutMs = 5000): Promise<Packet> {
    const queued = this.queue.shift();
    if (queued) return Promise.resolve(queued);
    return new Promise<Packet>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const waiter = (packet: Packet) => {
        if (timer !== undefined) clearTimeout(timer);
        resolve(packet);
      };
      timer = setTimeout(() => {
        const index = this.waiters.indexOf(waiter);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(new Error("packet timed out"));
      }, timeoutMs);
      this.waiters.push(waiter);
    });
  }

  send(type: number, streamId: number, payload?: Uint8Array): void {
    this.ws.send(encodePacket(type, streamId, payload));
  }

  close(): void {
    try {
      this.ws.close();
    } catch {
      // Already closed.
    }
  }
}

function parseExtensionIds(payload: Uint8Array): number[] {
  const ids: number[] = [];
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  let offset = 2;
  while (offset + 5 <= payload.length) {
    const id = payload[offset];
    const length = view.getUint32(offset + 1, true);
    offset += 5;
    if (offset + length > payload.length) break;
    ids.push(id);
    offset += length;
  }
  return ids;
}

function infoPayload(extraExtensions: Array<{ id: number; data?: Uint8Array }> = []): Uint8Array {
  const parts: Uint8Array[] = [Uint8Array.of(2, 1)];
  for (const extension of extraExtensions) {
    const data = extension.data ?? new Uint8Array(0);
    const entry = new Uint8Array(5 + data.length);
    entry[0] = extension.id;
    new DataView(entry.buffer).setUint32(1, data.length, true);
    entry.set(data, 5);
    parts.push(entry);
  }
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function connectPayload(port: number, host: string, kind: 1 | 2 = 1): Uint8Array {
  const hostBytes = new TextEncoder().encode(host);
  const out = new Uint8Array(3 + hostBytes.length);
  out[0] = kind;
  new DataView(out.buffer).setUint16(1, port, true);
  out.set(hostBytes, 3);
  return out;
}

function continueBuffer(payload: Uint8Array): number {
  return new DataView(payload.buffer, payload.byteOffset, payload.byteLength)
    .getUint32(0, true);
}

function startEchoServer(): { port: number; close: () => void } {
  const listener = Deno.listen({ hostname: HOST, port: 0 });
  const port = (listener.addr as Deno.NetAddr).port;
  let stopped = false;

  (async () => {
    for await (const conn of listener) {
      (async () => {
        const buffer = new Uint8Array(8192);
        try {
          while (true) {
            const read = await conn.read(buffer);
            if (read === null) break;
            await conn.write(buffer.subarray(0, read));
          }
        } catch {
          // Client went away.
        } finally {
          try {
            conn.close();
          } catch { /* already closed */ }
        }
      })().catch(() => {});
    }
  })().catch(() => {});

  return {
    port,
    close: () => {
      if (stopped) return;
      stopped = true;
      try {
        listener.close();
      } catch { /* already closed */ }
    },
  };
}

async function closedPort(): Promise<number> {
  const listener = Deno.listen({ hostname: HOST, port: 0 });
  const port = (listener.addr as Deno.NetAddr).port;
  listener.close();
  return port;
}

async function handshake(client: TestClient): Promise<number> {
  const info = await client.next();
  assertEquals(info.type, PACKET.INFO, "INFO packet type");
  assertEquals(info.streamId, 0, "INFO stream id");
  assertEquals(info.payload[0], 2, "Wisp major version");
  client.send(PACKET.INFO, 0, infoPayload([{ id: 0x05 }, { id: 0x01 }]));
  const credit = await client.next();
  assertEquals(credit.type, PACKET.CONTINUE, "handshake CONTINUE type");
  assertEquals(credit.streamId, 0, "handshake CONTINUE stream id");
  return continueBuffer(credit.payload);
}

Deno.test("v2: server advertises 2.1, UDP and stream confirmation, then grants credit", async () => {
  const server = await startServer(testConfig({ allowUdp: true }));
  const client = await TestClient.open(server.url(), ["wisp"]);
  try {
    const info = await client.next();
    assertEquals(info.type, PACKET.INFO);
    assertEquals(info.streamId, 0);
    assertEquals(info.payload[0], 2, "major version");
    assertEquals(info.payload[1], 1, "minor version");

    const extensionIds = parseExtensionIds(info.payload);
    assert(extensionIds.includes(0x01), "UDP extension advertised");
    assert(extensionIds.includes(0x05), "stream confirmation extension advertised");

    client.send(PACKET.INFO, 0, infoPayload([{ id: 0x05 }]));
    const credit = await client.next();
    assertEquals(credit.type, PACKET.CONTINUE);
    assertEquals(continueBuffer(credit.payload), 4, "initial credit equals buffer size");
  } finally {
    client.close();
    await server.stop();
  }
});

Deno.test("v2: TCP stream is multiplexed to the destination and echoes data back", async () => {
  const echo = startEchoServer();
  const server = await startServer(testConfig());
  const client = await TestClient.open(server.url(), ["wisp"]);
  try {
    await handshake(client);

    client.send(PACKET.CONNECT, 7, connectPayload(echo.port, HOST));
    const opened = await client.next();
    assertEquals(opened.type, PACKET.CONTINUE, "stream open confirmation");
    assertEquals(opened.streamId, 7);

    client.send(PACKET.DATA, 7, new TextEncoder().encode("hello wisp"));
    const echoed = await client.next();
    assertEquals(echoed.type, PACKET.DATA);
    assertEquals(echoed.streamId, 7);
    assertBytes(echoed.payload, "hello wisp");
  } finally {
    client.close();
    await server.stop();
    echo.close();
  }
});

Deno.test("v2: several streams stay independent on one websocket", async () => {
  const echo = startEchoServer();
  const server = await startServer(testConfig({ maxStreams: 4 }));
  const client = await TestClient.open(server.url(), ["wisp"]);
  try {
    await handshake(client);

    for (const streamId of [1, 2]) {
      client.send(PACKET.CONNECT, streamId, connectPayload(echo.port, HOST));
      const opened = await client.next();
      assertEquals(opened.streamId, streamId);
      assertEquals(opened.type, PACKET.CONTINUE);
    }

    client.send(PACKET.DATA, 1, new TextEncoder().encode("one"));
    client.send(PACKET.DATA, 2, new TextEncoder().encode("two"));

    const replies = [await client.next(), await client.next()];
    replies.sort((a, b) => a.streamId - b.streamId);
    assertEquals(replies[0].streamId, 1);
    assertBytes(replies[0].payload, "one");
    assertEquals(replies[1].streamId, 2);
    assertBytes(replies[1].payload, "two");
  } finally {
    client.close();
    await server.stop();
    echo.close();
  }
});

Deno.test("v1 fallback: no subprotocol means CONTINUE instead of INFO", async () => {
  const echo = startEchoServer();
  const server = await startServer(testConfig());
  const client = await TestClient.open(server.url());
  try {
    const credit = await client.next();
    assertEquals(credit.type, PACKET.CONTINUE, "v1 handshake packet");
    assertEquals(credit.streamId, 0);

    client.send(PACKET.CONNECT, 3, connectPayload(echo.port, HOST));
    const opened = await client.next();
    assertEquals(opened.streamId, 3);

    client.send(PACKET.DATA, 3, new TextEncoder().encode("v1 payload"));
    const echoed = await client.next();
    assertBytes(echoed.payload, "v1 payload");
  } finally {
    client.close();
    await server.stop();
    echo.close();
  }
});

Deno.test("policy: private destinations are blocked by default", async () => {
  const server = await startServer(testConfig({ allowPrivate: false }));
  const client = await TestClient.open(server.url(), ["wisp"]);
  try {
    await handshake(client);
    client.send(PACKET.CONNECT, 5, connectPayload(25565, "127.0.0.1"));
    const closed = await client.next();
    assertEquals(closed.type, PACKET.CLOSE);
    assertEquals(closed.streamId, 5);
    assertEquals(closed.payload[0], CLOSE_REASON.BLOCKED);
  } finally {
    client.close();
    await server.stop();
  }
});

Deno.test("policy: blocked host lists are honoured", async () => {
  const echo = startEchoServer();
  const server = await startServer(testConfig({ blockedHosts: ["127.0.0.1"] }));
  const client = await TestClient.open(server.url(), ["wisp"]);
  try {
    await handshake(client);
    client.send(PACKET.CONNECT, 6, connectPayload(echo.port, HOST));
    const closed = await client.next();
    assertEquals(closed.type, PACKET.CLOSE);
    assertEquals(closed.payload[0], CLOSE_REASON.BLOCKED);
  } finally {
    client.close();
    await server.stop();
    echo.close();
  }
});

Deno.test("policy: allow lists reject everything else", async () => {
  const echo = startEchoServer();
  const server = await startServer(testConfig({ allowedHosts: ["example.com"] }));
  const client = await TestClient.open(server.url(), ["wisp"]);
  try {
    await handshake(client);
    client.send(PACKET.CONNECT, 8, connectPayload(echo.port, HOST));
    const closed = await client.next();
    assertEquals(closed.type, PACKET.CLOSE);
    assertEquals(closed.payload[0], CLOSE_REASON.BLOCKED);
  } finally {
    client.close();
    await server.stop();
    echo.close();
  }
});

Deno.test("errors: a refused destination closes only that stream with 0x44", async () => {
  const port = await closedPort();
  const server = await startServer(testConfig());
  const client = await TestClient.open(server.url(), ["wisp"]);
  try {
    await handshake(client);
    client.send(PACKET.CONNECT, 9, connectPayload(port, HOST));
    const closed = await client.next();
    assertEquals(closed.type, PACKET.CLOSE);
    assertEquals(closed.streamId, 9);
    assertEquals(closed.payload[0], CLOSE_REASON.REFUSED);
  } finally {
    client.close();
    await server.stop();
  }
});

Deno.test("errors: unresolvable hostname closes the stream with 0x42", async () => {
  const server = await startServer(testConfig());
  const client = await TestClient.open(server.url(), ["wisp"]);
  try {
    await handshake(client);
    client.send(PACKET.CONNECT, 10, connectPayload(25565, "does-not-exist.invalid"));
    const closed = await client.next(15000);
    assertEquals(closed.type, PACKET.CLOSE);
    // DNS failure is 0x42; a resolver that stalls instead maps to 0x43.
    assert(
      closed.payload[0] === CLOSE_REASON.UNREACHABLE ||
        closed.payload[0] === CLOSE_REASON.TIMEOUT,
      `expected unreachable/timeout close, got ${closed.payload[0]}`,
    );
  } finally {
    client.close();
    await server.stop();
  }
});

Deno.test("limits: stream count above WISP_MAX_STREAMS is throttled", async () => {
  const echo = startEchoServer();
  const server = await startServer(testConfig({ maxStreams: 1 }));
  const client = await TestClient.open(server.url(), ["wisp"]);
  try {
    await handshake(client);
    client.send(PACKET.CONNECT, 11, connectPayload(echo.port, HOST));
    assertEquals((await client.next()).streamId, 11);

    client.send(PACKET.CONNECT, 12, connectPayload(echo.port, HOST));
    const rejected = await client.next();
    assertEquals(rejected.type, PACKET.CLOSE);
    assertEquals(rejected.streamId, 12);
    assertEquals(rejected.payload[0], CLOSE_REASON.THROTTLED);
  } finally {
    client.close();
    await server.stop();
    echo.close();
  }
});

Deno.test("lifecycle: client CLOSE stops relayed data on that stream", async () => {
  const echo = startEchoServer();
  const server = await startServer(testConfig());
  const client = await TestClient.open(server.url(), ["wisp"]);
  try {
    await handshake(client);
    client.send(PACKET.CONNECT, 13, connectPayload(echo.port, HOST));
    await client.next(); // stream open

    client.send(PACKET.CLOSE, 13, Uint8Array.of(CLOSE_REASON.VOLUNTARY));
    client.send(PACKET.DATA, 13, new TextEncoder().encode("should be dropped"));

    let leaked = false;
    try {
      await client.next(500);
      leaked = true;
    } catch {
      leaked = false;
    }
    assert(!leaked, "no data should arrive for a closed stream");
  } finally {
    client.close();
    await server.stop();
    echo.close();
  }
});

Deno.test("handshake: incompatible major version is rejected with 0x04", async () => {
  const server = await startServer(testConfig());
  const client = await TestClient.open(server.url(), ["wisp"]);
  try {
    await client.next(); // server INFO
    client.send(PACKET.INFO, 0, Uint8Array.of(1, 0));
    const closed = await client.next();
    assertEquals(closed.type, PACKET.CLOSE);
    assertEquals(closed.streamId, 0);
    assertEquals(closed.payload[0], CLOSE_REASON.INCOMPATIBLE);
  } finally {
    client.close();
    await server.stop();
  }
});

Deno.test("malformed: CONNECT on reserved stream id 0 is rejected", async () => {
  const server = await startServer(testConfig());
  const client = await TestClient.open(server.url(), ["wisp"]);
  try {
    await handshake(client);
    client.send(PACKET.CONNECT, 0, connectPayload(25565, "example.com"));
    const closed = await client.next();
    assertEquals(closed.type, PACKET.CLOSE);
    assertEquals(closed.streamId, 0);
    assertEquals(closed.payload[0], CLOSE_REASON.INVALID_INFO);
  } finally {
    client.close();
    await server.stop();
  }
});

Deno.test("http: plain GET returns the status document", async () => {
  const server = await startServer(testConfig({ allowUdp: true }));
  try {
    const response = await fetch(`http://${HOST}:${server.port}/functions/v1/wisp/`);
    assertEquals(response.status, 200);
    const body = await response.json() as { name: string; protocols: string[] };
    assertEquals(body.name, "supabase-wisp");
    assert(body.protocols.includes("wisp/2.1"), "advertises wisp/2.1");
  } finally {
    await server.stop();
  }
});

Deno.test("auth: configured token is required for the upgrade", async () => {
  const server = await startServer(testConfig({ token: "s3cret" }));
  try {
    const unauthorized = await fetch(`http://${HOST}:${server.port}/functions/v1/wisp/`, {
      headers: {
        upgrade: "websocket",
        connection: "upgrade",
        "sec-websocket-version": "13",
        "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
        "sec-websocket-protocol": "wisp",
      },
    });
    assertEquals(unauthorized.status, 401);
    await unauthorized.body?.cancel();
  } finally {
    await server.stop();
  }
});
