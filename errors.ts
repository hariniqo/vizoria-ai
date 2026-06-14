/**
 * errors.ts
 * ----------
 * Typed error classes for the VIZORIA AI authentication layer.
 *
 * Responsibility:
 *   - Provide a consistent, typed error vocabulary across all server functions.
 *   - Allow callers (route handlers, loaders) to discriminate error types and
 *     surface appropriate messages to the user without leaking internals.
 *   - Keep error codes stable so the client can map them to i18n strings later.
 *
 * Security note:
 *   - Public-facing messages are deliberately vague for sensitive failures
 *     (e.g. "Invalid email or password" rather than "Email not found") to
 *     prevent user-enumeration attacks.
 */

// ── BASE ──────────────────────────────────────────────────────────────────────
export class AuthError extends Error {
  constructor(
    message: string,
    public readonly code: AuthErrorCode,
    public readonly statusCode: number = 400
  ) {
    super(message);
    this.name = "AuthError";
  }
}

// ── ERROR CODES ───────────────────────────────────────────────────────────────
// String literals make it easy to match in switch/case without importing enums.
export type AuthErrorCode =
  | "VALIDATION_ERROR"        // Zod schema rejected the input
  | "DUPLICATE_EMAIL"         // User tried to register with an existing email
  | "INVALID_CREDENTIALS"     // Wrong email or password (intentionally vague)
  | "EMAIL_NOT_VERIFIED"      // User logged in before confirming their email
  | "TOKEN_EXPIRED"           // Password-reset link has expired
  | "TOKEN_INVALID"           // Password-reset token is malformed or used
  | "SESSION_MISSING"         // No active session found (unauthenticated)
  | "INSUFFICIENT_ROLE"       // User lacks the required role for this route
  | "OAUTH_ERROR"             // Google OAuth flow failed
  | "RATE_LIMITED"            // Too many requests; Supabase returned 429
  | "UNKNOWN_ERROR";          // Catch-all; internal details are logged, not exposed

// ── FACTORIES ─────────────────────────────────────────────────────────────────
// Centralised factories ensure consistent messages and HTTP status codes.

export const errors = {
  validation: (message: string) =>
    new AuthError(message, "VALIDATION_ERROR", 422),

  duplicateEmail: () =>
    new AuthError(
      "An account with this email already exists. Try logging in instead.",
      "DUPLICATE_EMAIL",
      409
    ),

  invalidCredentials: () =>
    new AuthError(
      "Invalid email or password. Please try again.",
      "INVALID_CREDENTIALS",
      401
    ),

  emailNotVerified: () =>
    new AuthError(
      "Please verify your email address before logging in. Check your inbox.",
      "EMAIL_NOT_VERIFIED",
      403
    ),

  tokenExpired: () =>
    new AuthError(
      "This password reset link has expired. Please request a new one.",
      "TOKEN_EXPIRED",
      410
    ),

  tokenInvalid: () =>
    new AuthError(
      "This password reset link is invalid or has already been used.",
      "TOKEN_INVALID",
      400
    ),

  sessionMissing: () =>
    new AuthError(
      "You must be logged in to access this resource.",
      "SESSION_MISSING",
      401
    ),

  insufficientRole: (required: string) =>
    new AuthError(
      `Access denied. This area requires the '${required}' role.`,
      "INSUFFICIENT_ROLE",
      403
    ),

  oauthError: (detail?: string) =>
    new AuthError(
      detail ?? "Google sign-in failed. Please try again.",
      "OAUTH_ERROR",
      400
    ),

  rateLimited: () =>
    new AuthError(
      "Too many attempts. Please wait a moment before trying again.",
      "RATE_LIMITED",
      429
    ),

  unknown: () =>
    new AuthError(
      "Something went wrong. Please try again later.",
      "UNKNOWN_ERROR",
      500
    ),
} as const;

// ── HELPER ────────────────────────────────────────────────────────────────────
/**
 * Maps a raw Supabase error message to a typed AuthError.
 * Supabase returns human-readable strings; this normalises them so we never
 * accidentally expose raw DB or auth-server internals to the client.
 */
export function mapSupabaseError(error: { message?: string; status?: number }): AuthError {
  const msg = (error.message ?? "").toLowerCase();
  const status = error.status ?? 0;

  if (status === 429) return errors.rateLimited();

  if (
    msg.includes("user already registered") ||
    msg.includes("email already in use") ||
    msg.includes("duplicate")
  ) {
    return errors.duplicateEmail();
  }

  if (
    msg.includes("invalid login credentials") ||
    msg.includes("email not confirmed") === false && msg.includes("invalid")
  ) {
    return errors.invalidCredentials();
  }

  if (msg.includes("email not confirmed")) {
    return errors.emailNotVerified();
  }

  if (msg.includes("token has expired") || msg.includes("otp expired")) {
    return errors.tokenExpired();
  }

  if (msg.includes("token") && msg.includes("invalid")) {
    return errors.tokenInvalid();
  }

  // Log the raw error server-side for debugging, but return a safe generic error.
  console.error("[VIZORIA AUTH] Unmapped Supabase error:", error);
  return errors.unknown();
}
