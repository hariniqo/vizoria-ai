/**
 * server.ts
 * ----------
 * Server-side Supabase client for VIZORIA AI.
 *
 * Responsibility:
 *   - Create a per-request Supabase client that reads cookies and verifies the
 *     user's JWT server-side — the only trustworthy way to authenticate a request.
 *   - Provide a privileged admin client (service-role) for operations that must
 *     bypass RLS, such as writing to `activity_logs` or reading `user_roles`.
 *
 * Security note:
 *   - SUPABASE_SERVICE_ROLE_KEY is a server-only secret. It bypasses RLS
 *     completely. It must NEVER be sent to the browser or placed in client.ts.
 *   - The per-request client (`createServerClient`) respects RLS because it
 *     uses the authenticated user's JWT, not the service-role key.
 */

import { createServerClient } from "@supabase/ssr";
import type { Database } from "@/types/database";

// TanStack Start / Vinxi exposes server env vars through process.env.
// These are never serialised into the client bundle.
const SUPABASE_URL = process.env.SUPABASE_URL!;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY!;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY!;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error(
    "[VIZORIA] Missing Supabase server environment variables. Check .env.local."
  );
}

// ── PER-REQUEST CLIENT (respects user session & RLS) ─────────────────────────
/**
 * Call this inside a `createServerFn` handler, passing the raw Request so
 * Supabase can read the auth cookies.
 *
 * @param request - The incoming HTTP request from TanStack Start.
 */
export function createSupabaseServerClient(request: Request) {
  // We need cookie helpers that work with TanStack Start's Vinxi runtime.
  const cookieHeader = request.headers.get("cookie") ?? "";

  return createServerClient<Database>(SUPABASE_URL, SUPABASE_ANON_KEY, {
    cookies: {
      getAll() {
        // Parse the raw cookie header into an array of { name, value } pairs.
        return cookieHeader.split(";").flatMap((pair) => {
          const [rawName, ...rest] = pair.trim().split("=");
          const name = rawName?.trim();
          const value = rest.join("=").trim();
          return name && value ? [{ name, value }] : [];
        });
      },
      // setAll / removeAll are no-ops here because the server functions use
      // Response headers set by session.ts to propagate cookie mutations.
      setAll() {},
      removeAll() {},
    },
  });
}

// ── ADMIN CLIENT (bypasses RLS — use sparingly) ───────────────────────────────
/**
 * A long-lived admin client used only for privileged operations:
 *   - Writing to activity_logs (needs to insert regardless of user's RLS policy)
 *   - Reading user_roles to verify permissions
 *   - Sending custom auth emails
 *
 * Never expose this client to user-controlled inputs.
 */
export function createSupabaseAdminClient() {
  return createServerClient<Database>(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: {
      // Service-role clients don't need session management.
      autoRefreshToken: false,
      persistSession: false,
    },
    cookies: {
      getAll: () => [],
      setAll: () => {},
    },
  });
}
