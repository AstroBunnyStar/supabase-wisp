# supabase-wisp

A [Wisp](https://github.com/MercuryWorkshop/wisp-protocol) relay that runs on **Supabase Edge Functions** (Deno), so browser clients that cannot open raw sockets — Eaglercraft, Scramjet/Ultraviolet, `libcurl.js`, any Wisp-capable proxy — get real TCP (and UDP) egress through `wss://<project-ref>.supabase.co/functions/v1/wisp/`.

- **Wisp v2** (major 2, minor 1) with a **v1 fallback** on the same endpoint.
- TCP + UDP streams, multiplexed over one WebSocket, with per-stream flow control.
- Written against the raw `Deno.upgradeWebSocket` API, so it deploys as a plain Supabase Edge Function — no Node HTTP server, no Docker, no extra host.
- Default-deny destination policy so a public relay can't be used to poke private networks or Supabase's own control plane.

> **Read [Limits](#limits-and-caveats) first.** Supabase caps a worker's wall-clock lifetime, which ends long Minecraft sessions. For hours-long play, use Deno Deploy or a VPS; this function is best for short sessions, testing, and browser tools.

---

## 1. Deploy

Prerequisites: a Supabase project and the [Supabase CLI](https://supabase.com/docs/guides/cli).

```bash
# from the root of this repo
supabase login
supabase link --project-ref <your-project-ref>

supabase functions deploy wisp --no-verify-jwt
```

`--no-verify-jwt` is **required by design**: a browser cannot attach an `Authorization` header to a WebSocket upgrade, so JWT verification would reject every real client. Protect the endpoint with `WISP_TOKEN` instead (see [Configuration](#configuration)). `supabase/config.toml` already sets `verify_jwt = false` for the function, so a bare `supabase functions deploy wisp` also works.

Your endpoint is:

```
wss://<your-project-ref>.supabase.co/functions/v1/wisp/
```

**Keep the trailing slash.** `@mercuryworkshop/wisp-js` builds `url + streamId` style paths and some clients/proxies are picky about the final `/`.

Quick health check (plain HTTP GET returns JSON, no upgrade):

```bash
curl https://<your-project-ref>.supabase.co/functions/v1/wisp
```

```json
{
  "name": "supabase-wisp",
  "version": "1.0.0",
  "protocols": ["wisp/2.1", "wisp/1"],
  "transports": ["tcp", "udp"],
  "auth": "open"
}
```

### Local development

```bash
supabase functions serve wisp --no-verify-jwt
# ws://127.0.0.1:54321/functions/v1/wisp/
```

`supabase/config.toml` sets `[edge_runtime] policy = "per_worker"`. Without it the local runtime tears the instance down after each request and WebSockets close immediately.

You can also run the handler with plain Deno, which is how the tests do it:

```bash
npx -y deno@2 run -A tests/interop/serve.ts   # listens on :18111
```

---

## 2. Point clients at it

### `@mercuryworkshop/wisp-js` (Scramjet, Ultraviolet, custom proxies)

```js
import { Client } from "@mercuryworkshop/wisp-js/client";

const client = new Client("wss://<your-project-ref>.supabase.co/functions/v1/wisp/");

// TCP
const stream = client.createStream();          // returns a WispStream
await stream.open("example.com", 80);
stream.send(new TextEncoder().encode("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"));
stream.onmessage = (data) => console.log(new TextDecoder().decode(data));

// with a token, when WISP_TOKEN is set
new Client("wss://<ref>.supabase.co/functions/v1/wisp/?token=<token>");
```

### `libcurl.js`

```html
<script src="https://cdn.jsdelivr.net/npm/@mercuryworkshop/libcurl.js/dist/libcurl.js"></script>
<script>
  libcurl.set_websocket("wss://<your-project-ref>.supabase.co/functions/v1/wisp/");
</script>
```

### Eaglercraft

EaglercraftX's official build talks to servers with its own WebSocket protocol (`ws://host:port/` handled by the server's EaglerXServer plugin), **not** Wisp. To use this relay you need a **Wisp-enabled client build or patch** — for example a wispcraft-patched client — and then set its Wisp URL to:

```
wss://<your-project-ref>.supabase.co/functions/v1/wisp/
```

The relay itself is protocol-correct and verified against the reference `wisp-js` client; whether a given Eaglercraft build can use it depends entirely on that build supporting Wisp. Stock EaglercraftX cannot.

---

## 3. Configuration

Set these as function secrets (never in the repo):

```bash
supabase secrets set WISP_TOKEN=some-long-random-string
```

Or, for local runs, in `supabase/functions/.env` (git-ignored) / real environment variables.

| Variable | Default | Meaning |
| --- | --- | --- |
| `WISP_TOKEN` | _unset_ | If set, upgrades must include `?token=<value>`, otherwise `401`. Browsers cannot send an auth header, so the query string is the only option. |
| `WISP_MOTD` | _unset_ | Message sent in the v2 `INFO` packet; clients may display it. |
| `WISP_MAX_STREAMS` | `16` | Concurrent streams per WebSocket (1–256). |
| `WISP_BUFFER_SIZE` | `64` | Per-stream buffered packets before `CONTINUE` is withheld (4–1024). |
| `WISP_RATE_LIMIT` | `2000` | Packets/second per connection; `0` disables the limiter. |
| `WISP_MAX_SECONDS` | `0` | Close the socket after N seconds (0 = no self-imposed limit, 1–3600). Useful to fail *predictably* before the platform reaps the worker. |
| `WISP_UDP` | `true` | Allow UDP streams (needed by some clients; disable if you only need TCP). |
| `WISP_ALLOW_PRIVATE` | `false` | Allow loopback / RFC1918 / link-local / CGNAT destinations. Never enable on a public deployment. |
| `WISP_ALLOWED_HOSTS` | _unset_ | Space/comma-separated allow-list, e.g. `mc.example.com *.example.net`. When set, everything else is refused. |
| `WISP_BLOCKED_HOSTS` | _unset_ | Extra deny patterns on top of the built-in list. `*.domain` matches subdomains, `*` matches everything. |
| `WISP_CONNECT_TIMEOUT_MS` | `10000` | TCP/UDP connect timeout (1000–30000). |
| `WISP_QUIET` | `true` | Log warnings/errors only. Set `false` for per-stream debug logs. |

Built-in deny list (always active unless `WISP_ALLOW_PRIVATE=true` covers the private-range part): `localhost`, `*.localhost`, `*.local`, `*.internal`, `*.home.arpa`, `metadata.google.internal`, `instance-data`, `*.supabase.co`, `*.supabase.in`, `*.supabase.red`, `*.pooler.supabase.com`, plus loopback/RFC1918/link-local/CGNAT/multicast literals.

A typical locked-down public relay:

```bash
supabase secrets set \
  WISP_TOKEN="$(openssl rand -hex 24)" \
  WISP_ALLOWED_HOSTS="mc.example.com play.example.net" \
  WISP_MAX_STREAMS=8 \
  WISP_MAX_SECONDS=120
```

---

## 4. Limits and caveats

These are Supabase platform facts, not bugs in the relay:

| Limit | Free | Paid |
| --- | --- | --- |
| Worker wall-clock per invocation | ~150 s | ~400 s |
| CPU time | 2 s | 2 s |
| Idle timeout | ~150 s | ~150 s |
| Memory | 256 MB | 256 MB |
| Blocked egress ports | 25, 587 | 25, 587 |

- **A WebSocket outlives the request only until the worker's wall clock runs out.** When the platform retires the worker, the TCP streams die. A Minecraft session therefore drops after roughly two minutes on free / six on paid. The handler uses `EdgeRuntime.waitUntil()` to keep the worker alive as long as the socket is open, but it cannot extend the platform's own limit.
- **`WISP_MAX_SECONDS`** lets you choose the cutoff so clients get a clean close instead of a silent drop. Clients reconnect; Eaglercraft will show a disconnect.
- **CPU is per-invocation, not per-byte**, and the relay only copies buffers, so bandwidth is not CPU-bound. Memory (256 MB) bounds how much can be buffered; the flow-control window keeps that in check.
- **Only ports 25 and 587 are blocked**, so normal game/HTTP ports work. Note that many Minecraft servers sit behind TCPShield etc.; those still work — you're just relaying TCP.
- **DNS rebinding is not defended against.** The host filter checks the requested name, not the resolved address.
- **No metrics.** Logs go to `supabase functions logs wisp`; `WISP_QUIET=false` adds per-connection detail.

**For long sessions**, deploy the same `wisp.ts` + `deno_relay.ts` core to Deno Deploy or a small VPS behind Caddy/nginx — the relay code is runtime-agnostic and only `handler.ts` is Supabase-specific.

---

## 5. How it works

```
browser ──wss──► Supabase Edge Function (Deno) ──tcp/udp──► target
                  index.ts → handler.ts → wisp.ts (protocol)
                                        └► deno_relay.ts (Deno.connect / connectUdp)
                                        └► policy.ts (destination filter)
```

- `wisp.ts` — packet codec (`0x01`–`0x05`), stream multiplexing, flow-control windows, close reasons, rate limiter. No Deno or Supabase APIs.
- `deno_relay.ts` — `Deno.connect` / `Deno.connectUdp` adapters with serialized writes and connect timeouts.
- `policy.ts` — hostname normalization, private-range detection, allow/block matching.
- `handler.ts` — status JSON, token check, v1/v2 detection, max-seconds timer, `EdgeRuntime.waitUntil`.
- `index.ts` — `Deno.serve(...)` entrypoint.

**v1 vs v2:** the Wisp spec selects v2 by the presence of `Sec-WebSocket-Protocol` on the upgrade. This relay echoes the offered token (the reference client offers `wisp-v2`) and sends an `INFO` packet; without the header it speaks v1 and sends `CONTINUE` on stream 0 instead.

---

## 6. Tests

```bash
npx -y deno@2 check supabase/functions/wisp/index.ts tests/wisp_test.ts
npx -y deno@2 test -A tests/
```

The suite starts real WebSocket clients against the handler and real TCP servers, covering: v2 handshake + echo, multiplexing, v1 fallback, private/blocked/allow-list policy, connection refused (`0x44`), DNS failure (`0x42`/`0x43`), stream limit (`0x49`), client close, incompatible version (`0x04`), stream-0 `CONNECT` rejection (`0x41`), the HTTP status document, and token `401`.

Interop against the reference implementation:

```bash
npx -y deno@2 run -A tests/interop/serve.ts          # :18111
WISP_URL=ws://127.0.0.1:18111/functions/v1/wisp/ node tests/interop/client.mjs
```

---

## 7. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `401 Unauthorized` on upgrade | `WISP_TOKEN` is set; append `?token=…`. |
| Socket opens then closes after ~2 min | Platform wall clock. Expected; see [Limits](#limits-and-caveats). Lower `WISP_MAX_SECONDS` to make it graceful. |
| Client connects, every stream closes with `0x44` | Destination refused/unreachable, or the host is in the deny list. Check `supabase functions logs wisp`. |
| Closes with `0x42`/`0x43` | DNS failure for the requested host from Supabase's network. |
| `0x41` on stream 0 | Client tried to `CONNECT` on stream 0; stream 0 is control-only in Wisp. |
| Works with `wisp-js`, not in my Eaglercraft build | That build does not speak Wisp. Use a Wisp-enabled build/patch. |
| Immediate close locally | Missing `[edge_runtime] policy = "per_worker"` in `supabase/config.toml`. |
| Deploy asks for a JWT | Deploy with `--no-verify-jwt` (or keep `verify_jwt = false` in `config.toml`). |

---

## Status

Verified **locally**: `deno check` clean, 15/15 end-to-end tests passing, and a real `@mercuryworkshop/wisp-js@0.5.3` v2 client completing a handshake and TCP echo through the relay. Not verified against a live Supabase deployment (no project credentials available when this was written) — do the `curl` health check after deploying.

## License

MIT
