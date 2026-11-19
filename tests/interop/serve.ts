// Local relay for interop checks: runs the same handler the Edge Function runs.
//
//   PORT=18111 WISP_ALLOW_PRIVATE=true deno run -A tests/interop/serve.ts
import { createHandler, loadConfigFromEnv } from "../../supabase/functions/wisp/handler.ts";

const port = Number(Deno.env.get("PORT") ?? "18111");
Deno.serve({ port, hostname: "127.0.0.1" }, createHandler(loadConfigFromEnv()));
console.log(`wisp relay listening on ws://127.0.0.1:${port}/functions/v1/wisp/`);
