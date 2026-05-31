"use client";

import { ChatSession } from "@/lib/types";

import {
  cn,
  truncateText,
  getModeLabel,
} from "@/lib/utils";

import { useChatStore } from "@/lib/store";

import {
  Trash2,
  ShieldAlert,
  FileSearch,
  Layers3,
} from "lucide-react";

import { formatDistanceToNow } from "date-fns";

interface Props {
  session: ChatSession;
  isActive: boolean;
}

export function SessionItem({
  session,
  isActive,
}: Props) {
  const {
    setActiveSession,
    deleteSession,
  } = useChatStore();

  const getModeIcon = () => {
    switch (session.mode) {
      case "threat_intelligence":
        return (
          <ShieldAlert className="w-3.5 h-3.5 text-violet-400" />
        );

      case "log_analysis":
        return (
          <FileSearch className="w-3.5 h-3.5 text-sky-400" />
        );

      default:
        return (
          <Layers3 className="w-3.5 h-3.5 text-emerald-400" />
        );
    }
  };

  return (
    <div
      onClick={() =>
        setActiveSession(session.id)
      }
      className={cn(
        "group cursor-pointer rounded-2xl p-4 transition-all",
        isActive
          ? "bg-[#111827] shadow-lg"
          : "hover:bg-white/5"
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          {getModeIcon()}

          <h4 className="text-sm text-white truncate">
            {truncateText(
              session.title || "New Investigation",
              36
            )}
          </h4>
        </div>

        <button
          onClick={(e) => {
            e.stopPropagation();
            deleteSession(session.id);
          }}
          className="opacity-0 group-hover:opacity-100 transition-opacity text-slate-500 hover:text-red-400"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="mt-3 flex items-center justify-between">
        <span className="text-[11px] text-slate-500">
          {getModeLabel(session.mode)}
        </span>

        <span className="text-[11px] text-slate-600">
          {formatDistanceToNow(
            new Date(session.createdAt),
            { addSuffix: true }
          )}
        </span>
      </div>

      {session.messages.length > 0 && (
        <p className="mt-2 text-xs text-slate-500 line-clamp-2">
          {
            session.messages[
              session.messages.length - 1
            ].content
          }
        </p>
      )}
    </div>
  );
}