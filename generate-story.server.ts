/**
 * src/lib/story/generate-story.server.ts
 * ---------------------------------------
 * createServerFn that validates input, verifies auth,
 * persists the concept, and returns a mock story response.
 *
 * Lovable pattern: ALL side-effects live here — never in the component.
 */

import { createServerFn } from "@tanstack/start";
import { z } from "zod";
import { createSupabaseServerClient } from "@/lib/auth/server";
import { verifySession } from "@/lib/auth/session";
import { errors } from "@/lib/auth/errors";

// ── INPUT SCHEMA ──────────────────────────────────────────────────────────────
const generateStorySchema = z.object({
  theory: z
    .string()
    .min(10, "Theory must be at least 10 characters")
    .max(1000, "Theory must be under 1000 characters")
    .trim(),
  subject: z
    .string()
    .min(2, "Subject is required")
    .max(100)
    .trim(),
});

export type GenerateStoryInput = z.infer<typeof generateStorySchema>;

// ── RESPONSE TYPE ─────────────────────────────────────────────────────────────
export interface StoryResponse {
  conceptId: string;
  story: {
    title: string;
    narrative: string;
    scenes: Array<{ sceneNumber: number; description: string }>;
  };
}

// ── SERVER FUNCTION ───────────────────────────────────────────────────────────
export const generateStory = createServerFn({ method: "POST" })
  .validator((data: unknown) => generateStorySchema.parse(data))
  .handler(async ({ data, request }): Promise<StoryResponse> => {
    // 1. Verify authenticated session (throws SESSION_MISSING if not logged in)
    const user = await verifySession(request);

    // 2. Get a per-request Supabase client that respects RLS
    const supabase = createSupabaseServerClient(request);

    // 3. Store the concept in the `concepts` table
    const { data: concept, error } = await supabase
      .from("concepts")
      .insert({
        user_id: user.id,
        theory: data.theory,
        subject: data.subject,
        status: "processing",
      })
      .select("id")
      .single();

    if (error) {
      console.error("[VIZORIA] concepts insert error:", error);
      throw errors.unknown();
    }

    // 4. Mock story generation (replace with AI call in Phase 3)
    const story = buildMockStory(data.theory, data.subject);

    // 5. Update concept status to completed
    await supabase
      .from("concepts")
      .update({ status: "completed" })
      .eq("id", concept.id);

    return { conceptId: concept.id, story };
  });

// ── MOCK STORY BUILDER ────────────────────────────────────────────────────────
function buildMockStory(theory: string, subject: string) {
  return {
    title: `The Story of ${subject}`,
    narrative: `Imagine a world where ${theory.slice(0, 80)}... This concept changed everything.`,
    scenes: [
      { sceneNumber: 1, description: `In the beginning, ${subject} was a mystery to all.` },
      { sceneNumber: 2, description: `A curious student discovered: ${theory.slice(0, 60)}...` },
      { sceneNumber: 3, description: `And so, the world understood ${subject} forever.` },
    ],
  };
}
