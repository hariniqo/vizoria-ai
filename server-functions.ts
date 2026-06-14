/**
 * server-functions.ts
 * --------------------
 * Complete createServerFn implementations for all VIZORIA AI authentication flows.
 *
 * Each function:
 *   1. Validates input with Zod (rejects bad data before touching Supabase).
 *   2. Performs the Supabase Auth operation.
 *   3. Writes an audit entry to `activity_logs` via the admin client.
 *   4. Returns a typed response or throws a typed AuthError.
 *
 * Security principle: Server functions are the only place credentials or tokens
 * are processed. The client never receives raw Supabase errors.
 */

import { createServerFn } from "@tanstack/start";
import { z } from "zod";
import {
  registrationSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
} from "./schemas";
import { createSupabaseServerClient, createSupabaseAdminClient } from "./server";
import { verifySession } from "./session";
import { errors, mapSupabaseError } from "./errors";
import type { AuthenticatedUser } from "./session";

// ── TYPES ────────────────────────────────────────────────────────────────────
interface AuthResponse {
  success: true;
  user: AuthenticatedUser;
}

interface MessageResponse {
  success: true;
  message: string;
}

// ── AUDIT LOGGER ─────────────────────────────────────────────────────────────
/**
 * Writes an event to `activity_logs` using the admin client (bypasses RLS).
 * Never throws — audit failures should not block the main auth flow.
 */
async function auditLog(params: {
  userId: string | null;
  action: string;
  metadata?: Record<string, unknown>;
}): Promise<void> {
  try {
    const admin = createSupabaseAdminClient();
    await admin.from("activity_logs").insert({
      user_id: params.userId,
      action: params.action,
      metadata: params.metadata ?? {},
      created_at: new Date().toISOString(),
    });
  } catch (err) {
    // Log to server console only — never surface audit errors to the client.
    console.error("[VIZORIA AUDIT] Failed to write activity log:", err);
  }
}

// ── REGISTER USER ─────────────────────────────────────────────────────────────
/**
 * Creates a new VIZORIA AI account.
 *
 * Flow:
 *  1. Validate input (Zod).
 *  2. Call supabase.auth.signUp — Supabase sends a verification email.
 *  3. The Phase 1 `handle_new_user` DB trigger fires automatically:
 *       - Creates a row in `profiles` with `full_name`.
 *       - Inserts a row in `user_roles` with role = 'student'.
 *  4. Audit the registration event.
 *
 * Duplicate email handling:
 *   Supabase returns an error if the email is already registered.
 *   mapSupabaseError converts this to DUPLICATE_EMAIL so the client
 *   can show a helpful "Try logging in instead" message.
 */
export const registerUser = createServerFn({ method: "POST" })
  .validator((data: unknown) => registrationSchema.parse(data))
  .handler(async ({ data, request }): Promise<MessageResponse> => {
    const supabase = createSupabaseServerClient(request);

    const { data: authData, error } = await supabase.auth.signUp({
      email: data.email,
      password: data.password,
      options: {
        // full_name is passed to the DB trigger via user_metadata.
        data: { full_name: data.fullName },
        // emailRedirectTo: where the user lands after clicking the verify link.
        emailRedirectTo: `${process.env.APP_URL}/auth/verify`,
      },
    });

    if (error) {
      throw mapSupabaseError(error);
    }

    // Supabase returns a user even for duplicates (security by obscurity).
    // Detect a "fake" response: identities array is empty for duplicate emails.
    if (authData.user && authData.user.identities?.length === 0) {
      throw errors.duplicateEmail();
    }

    await auditLog({
      userId: authData.user?.id ?? null,
      action: "user.registered",
      metadata: { email: data.email, method: "email_password" },
    });

    return {
      success: true,
      message:
        "Account created! Please check your inbox and verify your email before logging in.",
    };
  });

// ── LOGIN USER ────────────────────────────────────────────────────────────────
/**
 * Authenticates a user with email + password.
 *
 * Session persistence:
 *   Supabase @supabase/ssr writes HttpOnly cookies automatically when
 *   `createServerClient` handles the response. The cookie names are:
 *     sb-<project-ref>-auth-token       (access token)
 *     sb-<project-ref>-auth-token-code-verifier  (PKCE verifier)
 *
 * Redirect behaviour:
 *   The server function returns the authenticated user. The client-side
 *   router decides where to redirect (typically /dashboard).
 */
export const loginUser = createServerFn({ method: "POST" })
  .validator((data: unknown) => loginSchema.parse(data))
  .handler(async ({ data, request }): Promise<AuthResponse> => {
    const supabase = createSupabaseServerClient(request);

    const { data: authData, error } =
      await supabase.auth.signInWithPassword({
        email: data.email,
        password: data.password,
      });

    if (error) {
      // Map to vague "Invalid email or password" — never reveal which is wrong.
      throw mapSupabaseError(error);
    }

    const user = authData.user;

    // Enforce email verification before granting access.
    if (!user.email_confirmed_at) {
      throw errors.emailNotVerified();
    }

    await auditLog({
      userId: user.id,
      action: "user.login",
      metadata: { method: "email_password" },
    });

    return {
      success: true,
      user: {
        id: user.id,
        email: user.email ?? "",
        fullName: (user.user_metadata?.full_name as string | null) ?? null,
        emailVerified: true,
      },
    };
  });

// ── LOGOUT USER ───────────────────────────────────────────────────────────────
/**
 * Signs out the current user and invalidates the session.
 *
 * `scope: "local"` clears only this device's session.
 * Use `scope: "global"` to invalidate all sessions (e.g. after password change).
 */
export const logoutUser = createServerFn({ method: "POST" }).handler(
  async ({ request }): Promise<MessageResponse> => {
    const supabase = createSupabaseServerClient(request);

    // Best-effort: get userId for the audit log before destroying the session.
    let userId: string | null = null;
    try {
      const { data } = await supabase.auth.getUser();
      userId = data.user?.id ?? null;
    } catch {
      // Session may already be invalid; proceed with sign-out anyway.
    }

    const { error } = await supabase.auth.signOut({ scope: "local" });

    if (error) {
      console.error("[VIZORIA AUTH] Logout error:", error);
      // Even on error we attempt to clear the session — don't block the user.
    }

    await auditLog({ userId, action: "user.logout" });

    return { success: true, message: "You have been signed out." };
  }
);

// ── SIGN IN WITH GOOGLE (server-side exchange) ────────────────────────────────
/**
 * Exchanges the OAuth `code` (from the /auth/callback URL) for a Supabase session.
 * Called from the /auth/callback route loader after the Google redirect.
 *
 * This is the server-side half of the OAuth flow; the browser-side initiation
 * is in providers.ts → signInWithGoogle().
 */
export const exchangeGoogleCode = createServerFn({ method: "POST" })
  .validator((data: unknown) => z.object({ code: z.string().min(1) }).parse(data))
  .handler(async ({ data, request }): Promise<AuthResponse> => {
    const supabase = createSupabaseServerClient(request);

    const { data: sessionData, error } =
      await supabase.auth.exchangeCodeForSession(data.code);

    if (error) {
      throw errors.oauthError(error.message);
    }

    const user = sessionData.user;

    await auditLog({
      userId: user.id,
      action: "user.login",
      metadata: { method: "google_oauth" },
    });

    return {
      success: true,
      user: {
        id: user.id,
        email: user.email ?? "",
        fullName: (user.user_metadata?.full_name as string | null) ?? null,
        emailVerified: !!user.email_confirmed_at,
      },
    };
  });

// ── REQUEST PASSWORD RESET ────────────────────────────────────────────────────
/**
 * Sends a password-reset email containing a time-limited token link.
 *
 * Token strategy:
 *   Supabase generates a signed, one-time-use token and embeds it in the
 *   reset link as a URL fragment (#access_token=...). The link redirects to
 *   VITE_APP_URL/auth/reset-password where the user enters their new password.
 *
 * Security: We always return success even if the email is not registered.
 *   This prevents user-enumeration attacks (an attacker can't probe which
 *   emails exist by watching for "Email not found" vs "Email sent" responses).
 */
export const requestPasswordReset = createServerFn({ method: "POST" })
  .validator((data: unknown) => forgotPasswordSchema.parse(data))
  .handler(async ({ data, request }): Promise<MessageResponse> => {
    const supabase = createSupabaseServerClient(request);

    // Fire-and-forget: we don't await the result in the response path to
    // prevent timing attacks that could distinguish "found" from "not found".
    supabase.auth
      .resetPasswordForEmail(data.email, {
        redirectTo: `${process.env.APP_URL}/auth/reset-password`,
      })
      .then(({ error }) => {
        if (error) {
          // Log internally but never surface to the caller.
          console.error("[VIZORIA AUTH] Password reset email error:", error);
        }
      });

    await auditLog({
      userId: null, // We don't know the userId at this point (by design).
      action: "user.password_reset_requested",
      metadata: { email: data.email },
    });

    // Always return the same message regardless of whether the email exists.
    return {
      success: true,
      message:
        "If an account with that email exists, you will receive a reset link shortly.",
    };
  });

// ── RESET PASSWORD ────────────────────────────────────────────────────────────
/**
 * Updates the user's password using the token from the reset-password URL.
 *
 * Token validation:
 *   Supabase validates the token when `exchangeCodeForSession` is called
 *   (in the /auth/reset-password route loader, before this function is called).
 *   By the time updateUser() runs, the user is already in an authenticated
 *   session scoped to password reset only.
 *
 * Expired-link handling:
 *   If the token is expired or already used, `exchangeCodeForSession` throws
 *   an error with "Token has expired" — mapSupabaseError converts this to
 *   TOKEN_EXPIRED so the client can prompt the user to request a new link.
 *
 * After a successful reset:
 *   All other sessions are invalidated (`signOut({ scope: "global" })`) to
 *   protect against session fixation — if an attacker had an old session,
 *   changing the password revokes it.
 */
export const resetPassword = createServerFn({ method: "POST" })
  .validator((data: unknown) =>
    resetPasswordSchema.omit({ token: true }).parse(data)
  )
  .handler(async ({ data, request }): Promise<MessageResponse> => {
    const supabase = createSupabaseServerClient(request);

    // At this point the user must be in a password-reset session.
    // verifySession throws SESSION_MISSING if the token was not exchanged first.
    const user = await verifySession(request);

    const { error } = await supabase.auth.updateUser({
      password: data.newPassword,
    });

    if (error) {
      throw mapSupabaseError(error);
    }

    // Invalidate all other active sessions after the password change.
    // This runs asynchronously — we don't want to block the response.
    supabase.auth.signOut({ scope: "others" }).catch((e) =>
      console.error("[VIZORIA AUTH] Failed to revoke other sessions:", e)
    );

    await auditLog({
      userId: user.id,
      action: "user.password_reset_completed",
      metadata: { invalidated_other_sessions: true },
    });

    return {
      success: true,
      message: "Your password has been updated. Please log in with your new password.",
    };
  });

// ── GET CURRENT USER ──────────────────────────────────────────────────────────
/**
 * Returns the authenticated user from the current session.
 * Used by loaders to populate user state on protected pages.
 *
 * Returns null (does NOT throw) when there is no session, so loaders can
 * conditionally redirect without try/catch boilerplate everywhere.
 */
export const getCurrentUser = createServerFn({ method: "GET" }).handler(
  async ({ request }): Promise<AuthenticatedUser | null> => {
    try {
      return await verifySession(request);
    } catch {
      return null;
    }
  }
);
