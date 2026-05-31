"use client";

import { useEffect, useRef } from "react";

import { useChatStore } from "@/lib/store";

import { MessageBubble } from "./MessageBubble";
import { ChatInput } from "./ChatInput";
import { TypingIndicator } from "./TypingIndicator";

import { ModeSelector } from "../analysis/ModeSelector";

import { useChat } from "@/hooks/useChat";

import {
  Bot,
  Sparkles,
  MessageSquarePlus,
  ShieldAlert,
  FileSearch,
  Network,
} from "lucide-react";

import { getModeDescription } from "@/lib/utils";

export function ChatWindow() {
  const {
    getActiveSession,
    isLoading,
    currentMode,
    createSession,
  } = useChatStore();

  const { sendMessage } = useChat();

  const bottomRef =
    useRef<HTMLDivElement>(null);

  const session =
    getActiveSession();

  useEffect(() => {
    bottomRef.current?.scrollIntoView({
      behavior: "smooth",
    });
  }, [session?.messages, isLoading]);

  const handleNewChat = () =>
    createSession(currentMode);

  return (
    <div className="flex flex-col h-full">
      {/* Header */}

      <div className="px-8 py-5 border-b border-white/5 bg-[#0B1220]">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-2xl bg-gradient-to-br from-violet-500 to-sky-500 flex items-center justify-center">
              <Bot className="w-5 h-5 text-white" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h2 className="font-semibold text-white">
                  ThreatGraph AI
                </h2>

                <Sparkles className="w-4 h-4 text-violet-400" />
              </div>

              <p className="text-xs text-slate-500">
                Knowledge Graph Powered Security Assistant
              </p>
            </div>
          </div>

          <button
            onClick={handleNewChat}
            className="flex items-center gap-2 rounded-xl bg-white/5 hover:bg-white/10 px-4 py-2 transition-all text-slate-300"
          >
            <MessageSquarePlus className="w-4 h-4" />
            New Chat
          </button>
        </div>

        <div className="mt-4">
          <ModeSelector />
        </div>
      </div>

      {/* Messages */}

      <div className="flex-1 overflow-y-auto">
        {!session ||
        session.messages.length ===
          0 ? (
          <EmptyState
            mode={currentMode}
            onExample={sendMessage}
          />
        ) : (
          session.messages.map(
            (msg) => (
              <MessageBubble
                key={msg.id}
                message={msg}
              />
            )
          )
        )}

        {isLoading && (
          <TypingIndicator />
        )}

        <div ref={bottomRef} />
      </div>

      <ChatInput onSend={sendMessage} />
    </div>
  );
}

function EmptyState({
  mode,
  onExample,
}: {
  mode: Parameters<
    typeof getModeDescription
  >[0];
  onExample: (
    question: string
  ) => void;
}) {
  const EXAMPLES: Record<
    typeof mode,
    string[]
  > = {
    threat_intelligence: [
      "Analyze CVE-2021-44228",
      "Profile APT41",
      "Show ransomware attack patterns",
    ],

    log_analysis: [
      "Analyze failed SSH login attempts",
      "Review suspicious PowerShell activity",
      "Investigate Windows security events",
    ],

    combined: [
      "Correlate logs with MITRE ATT&CK",
      "Link traffic anomalies to threat actors",
      "Match indicators to known campaigns",
    ],
  };

  return (
    <div className="h-full flex flex-col items-center justify-center px-8">
      <div className="w-20 h-20 rounded-3xl bg-gradient-to-br from-violet-500 to-sky-500 flex items-center justify-center shadow-[0_20px_50px_rgba(59,130,246,0.25)]">
        <Bot className="w-10 h-10 text-white" />
      </div>

      <h1 className="mt-6 text-3xl font-bold text-white">
        ThreatGraph AI
      </h1>

      <p className="mt-2 text-slate-500 text-center max-w-xl">
        Security Copilot powered by
        Cyber Security Knowledge
        Graphs
      </p>

      <div className="grid md:grid-cols-3 gap-4 mt-10 w-full max-w-5xl">
        <FeatureCard
          icon={
            <ShieldAlert className="w-5 h-5" />
          }
          title="Threat Intelligence"
          desc="Malware investigation, CVE analysis, threat actor profiling."
        />

        <FeatureCard
          icon={
            <FileSearch className="w-5 h-5" />
          }
          title="Log Analysis"
          desc="Analyze suspicious events and security logs."
        />

        <FeatureCard
          icon={
            <Network className="w-5 h-5" />
          }
          title="Threat Correlation"
          desc="Connect logs with global threat intelligence."
        />
      </div>

      <div className="mt-10 w-full max-w-2xl space-y-2">
        {EXAMPLES[mode].map(
          (example) => (
            <button
              key={example}
              onClick={() =>
                onExample(example)
              }
              className="w-full text-left bg-[#111827] hover:bg-[#1F2937] rounded-2xl px-4 py-3 text-sm text-slate-300 transition-all"
            >
              {example}
            </button>
          )
        )}
      </div>
    </div>
  );
}

function FeatureCard({
  icon,
  title,
  desc,
}: {
  icon: React.ReactNode;
  title: string;
  desc: string;
}) {
  return (
    <div className="bg-[#111827] rounded-3xl p-5">
      <div className="text-violet-400">
        {icon}
      </div>

      <h3 className="mt-3 font-semibold text-white">
        {title}
      </h3>

      <p className="mt-2 text-sm text-slate-500">
        {desc}
      </p>
    </div>
  );
}