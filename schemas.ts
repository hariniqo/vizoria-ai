/**
 * schemas.ts
 * ----------
 * Zod validation schemas for all authentication flows in VIZORIA AI.
 *
 * Responsibility:
 *   - Define the shape and constraints for every auth-related form submission.
 *   - Serve as the single source of truth for validation (both client and server).
 *   - Strong password rules are enforced here so the server never accepts weak credentials.
 *
 * Used by: registerUser, loginUser, requestPasswordReset, resetPassword server functions.
 */

import { z } from "zod";

// ── PASSWORD RULE (shared across schemas) ────────────────────────────────────
// Minimum 8 chars, at least one uppercase, one lowercase, one digit, one special char.
// Keeping this as a reusable refinement avoids duplication between registration
// and password-reset schemas.
const strongPassword = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
  .regex(/[a-z]/, "Password must contain at least one lowercase letter")
  .regex(/[0-9]/, "Password must contain at least one number")
  .regex(
    /[^A-Za-z0-9]/,
    "Password must contain at least one special character"
  );

// ── REGISTRATION ─────────────────────────────────────────────────────────────
export const registrationSchema = z
  .object({
    fullName: z
      .string()
      .min(2, "Full name must be at least 2 characters")
      .max(100, "Full name must be under 100 characters")
      .regex(/^[a-zA-Z\s'-]+$/, "Full name contains invalid characters"),

    email: z
      .string()
      .email("Please enter a valid email address")
      .toLowerCase(), // normalise before storing

    password: strongPassword,

    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords do not match",
    path: ["confirmPassword"], // attach error to confirmPassword field
  });

export type RegistrationInput = z.infer<typeof registrationSchema>;

// ── LOGIN ────────────────────────────────────────────────────────────────────
export const loginSchema = z.object({
  email: z.string().email("Please enter a valid email address").toLowerCase(),
  password: z.string().min(1, "Password is required"),
});

export type LoginInput = z.infer<typeof loginSchema>;

// ── FORGOT PASSWORD ───────────────────────────────────────────────────────────
export const forgotPasswordSchema = z.object({
  email: z.string().email("Please enter a valid email address").toLowerCase(),
});

export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>;

// ── RESET PASSWORD ────────────────────────────────────────────────────────────
export const resetPasswordSchema = z
  .object({
    // The token comes from the URL query param (?token=...) sent by Supabase.
    // We validate it is a non-empty string; actual expiry is checked server-side.
    token: z.string().min(1, "Reset token is missing"),

    newPassword: strongPassword,

    confirmNewPassword: z.string(),
  })
  .refine((data) => data.newPassword === data.confirmNewPassword, {
    message: "Passwords do not match",
    path: ["confirmNewPassword"],
  });

export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;

// ── ROLE CHECK ────────────────────────────────────────────────────────────────
// Valid roles must match exactly the values stored in the `user_roles` table.
export const roleSchema = z.enum(["student", "teacher", "admin"]);

export type AppRole = z.infer<typeof roleSchema>;
