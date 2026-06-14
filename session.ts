/**
 * session.ts
 * ----------
 * Session management helpers for VIZORIA AI.
 *
 * Responsibility:
 *   - Retrieve and verify the current user's session inside server functions.
 *   - Propagate Set-Cookie headers back to the browser after Supabase mutates
 *     the session (login, logout, token refresh).
 *   - Provide a `getSession()` utility that is the foundation for every route guard.
 *
 * Security note:
 *   - We always call `supabase.auth.getUser()` (not `getSession()`) for
 *     authoritative identity checks. `getUser()` validates the JWT with
 *     Supabase's auth server on every call, preventing replay attacks with
 *     stolen, unrevoked tokens.
 *   - `getSession()` is only used where we need expiry metadata (not identity).
 */

import { createSupabaseServerClient } from "./server";
import { errors } from "./errors";

// ── TYPES ────────────────────────────────────────────────────────────────────
export interface AuthenticatedUser {
  id: string;
  email: string;
  fullName: string | null;
  emailVerified: boolean;
}

// ── VERIFY SESSION ────────────────────────────────────────────────────────────
/**
 * Validates the session attached to the incoming request and returns the
 * authenticated user. Throws `AuthError` with code SESSION_MISSING if there
 * is no valid session.
 *
 * Used as the base for all route guards in guards.ts.
 */
export async function verifySession(request: Request): Promise<AuthenticatedUser> {
  const supabase = createSupabaseServerClient(request);

  // getUser() makes a network request to Supabase Auth to validate the JWT.
  // This is slower than parsing the JWT locally but is cryptographically safe.
  const {
    data: { user },
    error,
  } = await supabase.auth.getUser();

  if (error || !user) {
    throw errors.sessionMissing();
  }

  return {
    id: user.id,
    email: user.email ?? "",
    fullName: (user.user_metadata?.full_name as string | null) ?? null,
    emailVerified: !!user.email_confirmed_at,
  };
}

// ── SET-COOKIE HEADER BUILDER ─────────────────────────────────────────────────
/**
 * After a Supabase auth operation (login, logout, refresh), Supabase needs to
 * set or clear cookies in the browser. TanStack Start server functions return
 * plain values, so we merge the Set-Cookie headers into a Headers object that
 * can be spread into the Response.
 *
 * Usage:
 *   const { headers } = buildCookieHeaders(cookiesToSet);
 *   return new Response(JSON.stringify(result), { headers });
 */
export function buildCookieHeaders(
  cookies: Array<{ name: string; value: string; options?: Record<string, unknown> }>
): { headers: Headers } {
  const headers = new Headers();

  for (const { name, value, options = {} } of cookies) {
    // Construct a minimal secure cookie string.
    const parts = [
      `${encodeURIComponent(name)}=${encodeURIComponent(value)}`,
      "Path=/",
      "HttpOnly",         // Prevent JS access — mitigates XSS token theft
      "SameSite=Lax",    // CSRF protection without breaking OAuth redirects
    ];

    if (process.env.NODE_ENV === "production") {
      parts.push("Secure"); // Only send over HTTPS in production
    }

    if (options.maxAge) {
      parts.push(`Max-Age=${options.maxAge}`);
    }

    if (options.expires) {
      parts.push(`Expires=${new Date(options.expires as number).toUTCString()}`);
    }

    headers.append("Set-Cookie", parts.join("; "));
  }

  return { headers };
}

// ── CLEAR SESSION COOKIES ─────────────────────────────────────────────────────
/**
 * Generates expired Set-Cookie headers to forcibly clear auth cookies on logout.
 * Supabase session cookies are prefixed with `sb-` followed by the project ref.
 */
export function clearSessionCookies(projectRef: string): { headers: Headers } {
  const cookieNames = [
    `sb-${projectRef}-auth-token`,
    `sb-${projectRef}-auth-token-code-verifier`, // PKCE flow
  ];

  const expired = cookieNames.map((name) => ({
    name,
    value: "",
    options: { expires: 0, maxAge: 0 },
  }));

  return buildCookieHeaders(expired);
}
