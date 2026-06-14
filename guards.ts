/**
 * guards.ts
 * ----------
 * Reusable route guards for VIZORIA AI server functions.
 *
 * Responsibility:
 *   - Verify that the caller is authenticated (requireAuth).
 *   - Verify that the caller holds a specific role (requireStudent / requireTeacher / requireAdmin).
 *   - Provide a composable, typed interface so guards can be applied in one line
 *     at the top of any createServerFn handler.
 *
 * Security design:
 *   - Role data is read from `user_roles` via the `has_role()` Postgres function,
 *     NOT from JWT claims or user metadata. This prevents a compromised client
 *     from self-assigning a higher role by manipulating its own JWT.
 *   - The admin client is used for role lookups because `user_roles` may have
 *     RLS that restricts a user from reading their own role (defence in depth).
 *     The admin client is never exposed to user input here.
 */

import { createSupabaseAdminClient } from "./server";
import { verifySession, type AuthenticatedUser } from "./session";
import { errors } from "./errors";
import type { AppRole } from "./schemas";

// ── TYPES ────────────────────────────────────────────────────────────────────
export interface GuardResult {
  user: AuthenticatedUser;
  role: AppRole;
}

// ── BASE: REQUIRE AUTH ────────────────────────────────────────────────────────
/**
 * Verifies the request has a valid Supabase session.
 * Throws SESSION_MISSING if not authenticated.
 *
 * @example
 * const { user } = await requireAuth(request);
 */
export async function requireAuth(request: Request): Promise<AuthenticatedUser> {
  // verifySession calls getUser() — cryptographically validated server-side.
  return verifySession(request);
}

// ── ROLE LOOKUP ───────────────────────────────────────────────────────────────
/**
 * Internal helper — reads the user's primary role from the DB using has_role().
 *
 * We check roles in priority order (admin → teacher → student) so a user who
 * holds multiple roles (possible during role transitions) gets the highest one.
 */
async function resolveRole(userId: string): Promise<AppRole> {
  const admin = createSupabaseAdminClient();

  // has_role() is a SECURITY DEFINER function (see Phase 1).
  // It runs as the DB owner, bypassing RLS, so we can safely check roles
  // without the user being able to influence the result.
  const roleChecks: AppRole[] = ["admin", "teacher", "student"];

  for (const role of roleChecks) {
    const { data, error } = await admin.rpc("has_role", {
      _user_id: userId,
      _role: role,
    });

    if (!error && data === true) {
      return role;
    }
  }

  // Every registered user should have at least the `student` role assigned by
  // the database trigger from Phase 1. If we reach here something is wrong.
  console.error(`[VIZORIA GUARD] No role found for user ${userId}`);
  throw errors.insufficientRole("student");
}

// ── REQUIRE STUDENT ───────────────────────────────────────────────────────────
/**
 * Allows access for users with any role (student, teacher, or admin) — because
 * teachers and admins are also allowed anywhere students are.
 *
 * @example
 * const { user, role } = await requireStudent(request);
 */
export async function requireStudent(request: Request): Promise<GuardResult> {
  const user = await requireAuth(request);
  const role = await resolveRole(user.id);

  // All authenticated, role-holding users can access student routes.
  if (!["student", "teacher", "admin"].includes(role)) {
    throw errors.insufficientRole("student");
  }

  return { user, role };
}

// ── REQUIRE TEACHER ───────────────────────────────────────────────────────────
/**
 * Allows access only for teachers and admins.
 *
 * @example
 * const { user, role } = await requireTeacher(request);
 */
export async function requireTeacher(request: Request): Promise<GuardResult> {
  const user = await requireAuth(request);
  const role = await resolveRole(user.id);

  if (!["teacher", "admin"].includes(role)) {
    throw errors.insufficientRole("teacher");
  }

  return { user, role };
}

// ── REQUIRE ADMIN ─────────────────────────────────────────────────────────────
/**
 * Allows access only for admins.
 *
 * @example
 * const { user } = await requireAdmin(request);
 */
export async function requireAdmin(request: Request): Promise<GuardResult> {
  const user = await requireAuth(request);
  const role = await resolveRole(user.id);

  if (role !== "admin") {
    throw errors.insufficientRole("admin");
  }

  return { user, role };
}

// ── USAGE EXAMPLE (in a createServerFn) ──────────────────────────────────────
/*
import { createServerFn } from "@tanstack/start";
import { requireTeacher } from "@/lib/auth/guards";

// Only teachers and admins can create a lesson.
export const createLesson = createServerFn({ method: "POST" })
  .handler(async ({ request, data }) => {
    const { user } = await requireTeacher(request);

    // Proceed knowing `user` is a verified teacher or admin.
    const lesson = await db.lessons.create({ ...data, authorId: user.id });
    return lesson;
  });
*/
