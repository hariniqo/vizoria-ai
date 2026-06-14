/**
 * src/components/story/StoryGenerator.tsx
 * ----------------------------------------
 * Minimal UI component that calls generateStory and displays the result.
 * No state management library needed — React state + server fn is enough.
 */

import { useState } from "react";
import { generateStory, type StoryResponse } from "@/lib/story/generate-story.server";

export function StoryGenerator() {
  const [theory, setTheory] = useState("");
  const [subject, setSubject] = useState("");
  const [story, setStory] = useState<StoryResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setStory(null);

    try {
      // Direct call — TanStack Start handles the HTTP transport automatically.
      const result = await generateStory({ data: { theory, subject } });
      setStory(result);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Something went wrong.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-2xl mx-auto p-6 space-y-6">
      <h1 className="text-2xl font-bold text-white">VIZORIA — Generate Story</h1>

      {/* Input form */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm text-gray-300 mb-1">Subject</label>
          <input
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder="e.g. Photosynthesis"
            className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-violet-500"
            required
          />
        </div>

        <div>
          <label className="block text-sm text-gray-300 mb-1">Theory</label>
          <textarea
            value={theory}
            onChange={(e) => setTheory(e.target.value)}
            placeholder="Explain the concept you want to visualize..."
            rows={4}
            className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-violet-500 resize-none"
            required
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-violet-600 hover:bg-violet-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-2.5 rounded-lg transition-colors"
        >
          {loading ? "Generating story…" : "Generate Story"}
        </button>
      </form>

      {/* Error state */}
      {error && (
        <div className="bg-red-500/20 border border-red-500/40 rounded-lg p-4 text-red-300 text-sm">
          {error}
        </div>
      )}

      {/* Story result */}
      {story && (
        <div className="bg-white/5 border border-white/10 rounded-xl p-6 space-y-4">
          <h2 className="text-xl font-bold text-violet-300">{story.story.title}</h2>
          <p className="text-gray-300 text-sm leading-relaxed">{story.story.narrative}</p>

          <div className="space-y-3 pt-2">
            {story.story.scenes.map((scene) => (
              <div
                key={scene.sceneNumber}
                className="flex gap-3 items-start"
              >
                <span className="text-violet-400 font-bold text-sm shrink-0">
                  Scene {scene.sceneNumber}
                </span>
                <p className="text-gray-400 text-sm">{scene.description}</p>
              </div>
            ))}
          </div>

          <p className="text-xs text-gray-600 pt-2">Concept ID: {story.conceptId}</p>
        </div>
      )}
    </div>
  );
}
