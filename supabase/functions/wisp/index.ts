// Supabase Edge Function entrypoint.
// Deploy with: supabase functions deploy wisp --no-verify-jwt
import { createHandler, loadConfigFromEnv } from "./handler.ts";

Deno.serve(createHandler(loadConfigFromEnv()));
