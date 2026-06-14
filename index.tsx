/**
 * src/routes/story/index.tsx
 * ---------------------------
 * TanStack Start file-based route for /story.
 * The loader enforces authentication before the component mounts.
 */

import { createFileRoute, redirect } from "@tanstack/react-router";
import { getCurrentUser } from "@/lib/auth/server-functions";
import { StoryGenerator } from "@/components/story/StoryGenerator";

export const Route = createFileRoute("/story/")({
  // Loader runs on the server before render — unauthenticated users never
  // reach the component; they get redirected to /login immediately.
  loader: async ({ context }) => {
    const user = await getCurrentUser({ request: context.request });
    if (!user) throw redirect({ to: "/login" });
    return { user };
  },

  component: function StoryPage() {
    return (
      <main className="min-h-screen bg-[#080B1F] py-12">
        <StoryGenerator />
      </main>
    );
  },
});
