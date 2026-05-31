"use client";

import { Message } from "@/lib/types";

import {
  formatTimestamp,
  getModeLabel,
  cn,
} from "@/lib/utils";

import { useChatStore } from "@/lib/store";

import {
  Bot,
  User2,
  Cpu,
  BookOpen,
  Network,
} from "lucide-react";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

interface Props {
  message: Message;
}

export function MessageBubble({
  message,
}: Props) {
  const { toggleGraphViewer } = useChatStore();

  const isUser = message.role === "user";

  return (
    <div
      className={cn(
        "px-6 py-4",
        isUser ? "flex justify-end" : "flex"
      )}
    >
      <div
        className={cn(
          "flex gap-3 max-w-4xl",
          isUser
            ? "flex-row-reverse"
            : "flex-row"
        )}
      >
        {/* Avatar */}

        <div
          className={cn(
            "w-9 h-9 rounded-2xl flex items-center justify-center flex-shrink-0",
            isUser
              ? "bg-violet-600"
              : "bg-gradient-to-br from-violet-500 to-sky-500"
          )}
        >
          {isUser ? (
            <User2 className="w-4 h-4 text-white" />
          ) : (
            <Bot className="w-4 h-4 text-white" />
          )}
        </div>

        {/* Content */}

        <div
          className={cn(
            "flex flex-col",
            isUser && "items-end"
          )}
        >
          {/* Bubble */}

          <div
            className={cn(
              "rounded-3xl px-5 py-4 text-sm leading-7",
              isUser
                ? "bg-gradient-to-r from-violet-600 to-indigo-600 text-white shadow-lg rounded-tr-md"
                : "bg-[#111827] text-slate-200 shadow-[0_8px_24px_rgba(0,0,0,0.25)] rounded-tl-md"
            )}
          >
            {isUser ? (
              <p>{message.content}</p>
            ) : (
              <div className="prose prose-invert max-w-none">
                <ReactMarkdown
                  remarkPlugins={[remarkGfm]}
                >
                  {message.content}
                </ReactMarkdown>
              </div>
            )}
          </div>

          {/* Meta */}

          <div className="flex flex-wrap items-center gap-3 mt-2 px-2 opacity-70">
            <span className="text-[11px] text-slate-500">
              {formatTimestamp(
                message.timestamp
              )}
            </span>

            {message.llmUsed && (
              <span className="flex items-center gap-1 text-[11px] text-slate-500">
                <Cpu className="w-3 h-3" />
                {message.llmUsed}
              </span>
            )}

            {message.mode &&
              !isUser && (
                <span className="text-[11px] text-slate-500">
                  {getModeLabel(
                    message.mode
                  )}
                </span>
              )}

            {message.sources &&
              message.sources.length >
                0 && (
                <span className="flex items-center gap-1 text-[11px] text-slate-500">
                  <BookOpen className="w-3 h-3" />
                  {message.sources.join(
                    ", "
                  )}
                </span>
              )}

            {message.triples &&
              message.triples.length >
                0 && (
                <button
                  onClick={() =>
                    toggleGraphViewer(
                      message
                    )
                  }
                  className="flex items-center gap-1 bg-violet-500/10 hover:bg-violet-500/20 text-violet-300 px-2 py-1 rounded-full text-[11px] transition-all"
                >
                  <Network className="w-3 h-3" />

                  {
                    message.triples
                      .length
                  }{" "}
                  triples
                </button>
              )}
          </div>
        </div>
      </div>
    </div>
  );
}