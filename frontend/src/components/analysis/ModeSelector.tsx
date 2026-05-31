"use client";

import { useChatStore } from "@/lib/store";
import { AnalysisMode } from "@/lib/types";

import {
  ShieldAlert,
  FileSearch,
  Network,
} from "lucide-react";

import { cn } from "@/lib/utils";

const MODES: {
  mode: AnalysisMode;
  label: string;
  icon: React.ReactNode;
}[] = [
  {
    mode: "threat_intelligence",
    label: "Threat Intelligence",
    icon: <ShieldAlert className="w-4 h-4" />,
  },
  {
    mode: "log_analysis",
    label: "Log Analysis",
    icon: <FileSearch className="w-4 h-4" />,
  },
  {
    mode: "combined",
    label: "Threat Correlation",
    icon: <Network className="w-4 h-4" />,
  },
];

export function ModeSelector() {
  const {
    currentMode,
    setCurrentMode,
  } = useChatStore();

  return (
    <div className="flex flex-wrap gap-2">
      {MODES.map((item) => (
        <button
          key={item.mode}
          onClick={() =>
            setCurrentMode(item.mode)
          }
          className={cn(
            "flex items-center gap-2 px-4 py-2 rounded-2xl text-sm transition-all",

            currentMode === item.mode
              ? "bg-violet-600 text-white shadow-lg"
              : "bg-white/5 hover:bg-white/10 text-slate-400"
          )}
        >
          {item.icon}

          <span>{item.label}</span>
        </button>
      ))}
    </div>
  );
}