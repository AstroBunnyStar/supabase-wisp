/**
 * Interop check with the reference client (@mercuryworkshop/wisp-js), the same
 * client library used by libcurl.js, Scramjet and Wisp-enabled Eaglercraft
 * builds.
 *
 *   1. npm install --no-save @mercuryworkshop/wisp-js
 *   2. PORT=18111 WISP_ALLOW_PRIVATE=true deno run -A tests/interop/serve.ts
 *   3. WISP_URL=ws://127.0.0.1:18111/functions/v1/wisp/ node tests/interop/client.mjs
 */
import net from "node:net";
import { client } from "@mercuryworkshop/wisp-js/client";

const WISP_URL = process.env.WISP_URL ?? "ws://127.0.0.1:18111/functions/v1/wisp/";

function fail(message) {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

const echo = net.createServer((socket) => socket.pipe(socket));
await new Promise((resolve, reject) => {
  echo.once("error", reject);
  echo.listen(0, "127.0.0.1", resolve);
});
const echoPort = echo.address().port;

const connection = new client.ClientConnection(WISP_URL);
await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("handshake timed out")), 10000);
  connection.onopen = () => {
    clearTimeout(timer);
    resolve();
  };
  connection.onerror = () => {
    clearTimeout(timer);
    reject(new Error("connection errored"));
  };
}).catch((error) => fail(error.message));

const stream = connection.create_stream("127.0.0.1", echoPort, "tcp");
const payload = new TextEncoder().encode(`interop-ping-${Date.now()}`);

const echoed = await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("stream timed out")), 10000);
  stream.onmessage = (data) => {
    clearTimeout(timer);
    resolve(new Uint8Array(data));
  };
  stream.onclose = () => {
    clearTimeout(timer);
    reject(new Error("stream closed before echoing"));
  };
  stream.send(payload);
}).catch((error) => fail(error.message));

const expected = new TextDecoder().decode(payload);
const actual = new TextDecoder().decode(echoed);
if (actual !== expected) fail(`echo mismatch: expected "${expected}", got "${actual}"`);

console.log(`PASS: wisp-js v2 client handshake + TCP echo (${actual.length} bytes)`);
connection.close();
echo.close();
