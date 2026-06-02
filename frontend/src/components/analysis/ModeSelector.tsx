"use client";

import { useChatStore } from "@/lib/store";
import { Cpu } from "lucide-react";

/**
 * Pemilih model LLM untuk perbandingan (mis. 2 model OpenRouter).
 * Daftar model diambil dari backend (/api/models) saat aplikasi dimuat.
 */
export function ModelSelector() {
  const { currentModel, availableModels, setCurrentModel } = useChatStore();

  if (!availableModels.length) return null;

  return (
    <div className="flex items-center gap-2">
      <Cpu className="w-4 h-4 text-[#495A43]" />
      <select
        value={currentModel}
        onChange={(e) => setCurrentModel(e.target.value)}
        className="bg-[#495A43]/20 border border-[#495A43] text-[#2F4128] text-sm rounded-2xl px-3 py-2 cursor-pointer focus:outline-none max-w-[260px]"
        title="Pilih model LLM (untuk perbandingan)"
      >
        {availableModels.map((m) => (
          <option key={m} value={m}>
            {m}
          </option>
        ))}
      </select>
    </div>
  );
}
