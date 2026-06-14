/**
 * providers.ts
 * ----------
 * OAuth provider configuration for VIZORIA AI.
 *
 * Responsibility:
 *   - Centralise redirect URIs and provider-specific config in one place.
 *   - Provide a typed `signInWithGoogle` helper that initiates the OAuth dance.
 *   - Document what must be configured in the Supabase dashboard and Google
 *     Cloud Console for OAuth to work.
 *
 * Setup checklist (do this once per environment):
 *
 *  1. Google Cloud Console → APIs & Services → Credentials → OAuth 2.0 Client:
 *       Authorised redirect URI: https://<your-supabase-project>.supabase.co/auth/v1/callback
 *
 *  2. Supabase Dashboard → Authentication → Providers → Google:
 *       Client ID:     (from Google Console)
 *       Client Secret: (from Google Console)
 *       Redirect URL:  https://vizoria.ai/auth/callback   ← your app's callback page
 *
 *  3. Set VITE_APP_URL in your .env files per environment.
 */

import { supabaseClient } from "./client";
import { errors } from "./errors";

// ── REDIRECT URI ──────────────────────────────────────────────────────────────
// TanStack Start handles the callback at /auth/callback (create this route).
// Supabase will redirect to this URL after a successful OAuth handshake,
// appending a `code` query param that must be exchanged for a session.
function getAuthCallbackUrl(): string {
  const appUrl =
    import.meta.env.VITE_APP_URL ??
    (typeof window !== "undefined" ? window.location.origin : "http://localhost:3000");

  return `${appUrl}/auth/callback`;
}

// ── GOOGLE OAUTH (client-side initiation) ─────────────────────────────────────
/**
 * Initiates the Google OAuth PKCE flow from the browser.
 *
 * Flow:
 *   1. Browser calls signInWithGoogle() → Supabase generates a code_verifier +
 *      code_challenge (PKCE) and redirects to Google's consent screen.
 *   2. User authenticates with Google.
 *   3. Google redirects back to Supabase's auth endpoint.
 *   4. Supabase validates the code, creates/links the user, and redirects to
 *      VITE_APP_URL/auth/callback?code=...
 *   5. The /auth/callback route exchanges the code for a session using
 *      `supabase.auth.exchangeCodeForSession(code)`.
 *
 * First-login provisioning:
 *   - If the Google email does not exist in auth.users, Supabase creates a new
 *     user automatically.
 *   - The `handle_new_user` trigger (Phase 1) fires, creating the `profiles`
 *     row and assigning the default `student` role — same path as email/password.
 *
 * Existing user linking:
 *   - If a user previously registered with email/password using the same email,
 *     Supabase will link the Google identity to the existing account IF
 *     "Link accounts" is enabled in Supabase Dashboard → Auth → Settings.
 *   - This is the default Supabase behaviour — no extra code required.
 */
export async function signInWithGoogle(): Promise<void> {
  const { error } = await supabaseClient.auth.signInWithOAuth({
    provider: "google",
    options: {
      redirectTo: getAuthCallbackUrl(),
      queryParams: {
        // Request offline access so we get a refresh token for long sessions.
        access_type: "offline",
        // "select_account" forces Google to show the account picker even when
        // the user is already logged into one Google account — better UX for
        // users with multiple accounts.
        prompt: "select_account",
      },
    },
  });

  if (error) {
    throw errors.oauthError(error.message);
  }

  // The browser is redirected to Google — no further action needed in this function.
}

// ── AUTH CALLBACK HANDLER (used in the /auth/callback route) ──────────────────
/**
 * Exchanges the `code` from the OAuth callback URL for a real Supabase session.
 * Call this inside the TanStack Start loader for /auth/callback.
 *
 * @example
 * // src/routes/auth/callback.ts
 * import { exchangeOAuthCode } from "@/lib/auth/providers";
 *
 * export const Route = createFileRoute("/auth/callback")({
 *   loader: async ({ location }) => {
 *     const code = new URL(location.href).searchParams.get("code");
 *     if (code) await exchangeOAuthCode(code);
 *     throw redirect({ to: "/dashboard" });
 *   },
 * });
 */
export async function exchangeOAuthCode(code: string): Promise<void> {
  const { error } = await supabaseClient.auth.exchangeCodeForSession(code);

  if (error) {
    throw errors.oauthError(error.message);
  }
}
