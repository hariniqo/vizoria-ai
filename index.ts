/**
 * index.ts
 * ----------
 * Barrel export for the VIZORIA AI auth library.
 * Import from "@/lib/auth" to get everything you need.
 *
 * Usage examples:
 *   import { registerUser, loginUser } from "@/lib/auth";
 *   import { requireAdmin }           from "@/lib/auth";
 *   import { registrationSchema }     from "@/lib/auth";
 */

// Schemas & types
export * from "./schemas";

// Typed errors
export * from "./errors";

// Client-side Supabase singleton
export { supabaseClient, getClientUser } from "./client";

// Server-side Supabase factory functions (server only)
export { createSupabaseServerClient, createSupabaseAdminClient } from "./server";

// Session utilities
export { verifySession, buildCookieHeaders, clearSessionCookies } from "./session";
export type { AuthenticatedUser } from "./session";

// Route guards
export { requireAuth, requireStudent, requireTeacher, requireAdmin } from "./guards";
export type { GuardResult } from "./guards";

// OAuth providers
export { signInWithGoogle, exchangeOAuthCode } from "./providers";

// Server functions
export {
  registerUser,
  loginUser,
  logoutUser,
  exchangeGoogleCode,
  requestPasswordReset,
  resetPassword,
  getCurrentUser,
} from "./server-functions";
