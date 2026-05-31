"use client";

import { useChatStore } from "@/lib/store";

import {
  Bot,
  Network,
  Trash2,
} from "lucide-react";

import { SessionItem } from "./SessionItem";

interface Props {
  onToggleGraph: () => void;
  isGraphOpen: boolean;
}

export function Sidebar({
  onToggleGraph,
  isGraphOpen,
}: Props) {
  const {
    sessions,
    activeSessionId,
    clearAllSessions,
  } = useChatStore();

  return (
    <div className="flex flex-col h-full bg-[#0F172A] shadow-[8px_0_32px_rgba(0,0,0,0.35)]">
      {/* Header */}

      <div className="px-5 py-6">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-2xl bg-gradient-to-br from-violet-500 to-sky-500 flex items-center justify-center shadow-lg">
            <Bot className="w-5 h-5 text-white" />
          </div>

          <div>
            <h2 className="font-semibold text-white">
              ThreatGraph AI
            </h2>

            <p className="text-xs text-slate-500">
              Security Copilot
            </p>
          </div>
        </div>
      </div>

      {/* Graph Button */}

      <div className="px-4">
        <button
          onClick={onToggleGraph}
          className={`w-full flex items-center justify-center gap-2 rounded-2xl px-4 py-3 transition-all ${
            isGraphOpen
              ? "bg-violet-600 text-white"
              : "bg-white/5 hover:bg-white/10 text-slate-300"
          }`}
        >
          <Network className="w-4 h-4" />

          <span className="text-sm font-medium">
            Knowledge Graph
          </span>
        </button>
      </div>

      {/* Session Label */}

      <div className="px-5 pt-6 pb-2">
        <p className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
          Session History
        </p>
      </div>

      {/* Sessions */}

      <div className="flex-1 overflow-y-auto px-3 pb-4">
        {sessions.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-4">
            <div className="w-14 h-14 rounded-2xl bg-white/5 flex items-center justify-center mb-3">
              <Bot className="w-6 h-6 text-slate-500" />
            </div>

            <p className="text-sm text-slate-400">
              No investigations yet
            </p>

            <p className="text-xs text-slate-600 mt-1">
              Start a new analysis to create a session
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {sessions.map((session) => (
              <SessionItem
                key={session.id}
                session={session}
                isActive={
                  session.id === activeSessionId
                }
              />
            ))}
          </div>
        )}
      </div>

      {/* Footer */}

      {sessions.length > 0 && (
        <div className="p-4">
          <button
            onClick={clearAllSessions}
            className="w-full flex items-center justify-center gap-2 rounded-2xl bg-white/5 hover:bg-red-500/10 text-slate-400 hover:text-red-400 py-3 transition-all"
          >
            <Trash2 className="w-4 h-4" />

            <span className="text-sm">
              Clear History
            </span>
          </button>
        </div>
      )}
    </div>
  );
}