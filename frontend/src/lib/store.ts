import { create } from "zustand";
import { persist } from "zustand/middleware";
import { AnalysisMode, ChatSession, Message } from "./types";
import { generateId } from "./utils";

interface ChatStore {
  sessions: ChatSession[];
  activeSessionId: string | null;
  currentMode: AnalysisMode;
  isLoading: boolean;
  isGraphViewerOpen: boolean;
  selectedMessage: Message | null;

  // Actions
  createSession: (mode?: AnalysisMode) => string;
  setActiveSession: (id: string) => void;
  deleteSession: (id: string) => void;
  addMessage: (sessionId: string, message: Omit<Message, "id" | "timestamp">) => void;
  setCurrentMode: (mode: AnalysisMode) => void;
  setLoading: (loading: boolean) => void;
  toggleGraphViewer: (message?: Message) => void;
  getActiveSession: () => ChatSession | null;
  clearAllSessions: () => void;
}

export const useChatStore = create<ChatStore>()(
  persist(
    (set, get) => ({
      sessions: [],
      activeSessionId: null,
      currentMode: "threat_intelligence",
      isLoading: false,
      isGraphViewerOpen: false,
      selectedMessage: null,

      createSession: (mode) => {
        const id = generateId();
        const m = mode ?? get().currentMode;
        const session: ChatSession = {
          id,
          title: "New Session",
          mode: m,
          messages: [],
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        set((s) => ({
          sessions: [session, ...s.sessions],
          activeSessionId: id,
        }));
        return id;
      },

      setActiveSession: (id) => set({ activeSessionId: id }),

      deleteSession: (id) =>
        set((s) => {
          const sessions = s.sessions.filter((s) => s.id !== id);
          return {
            sessions,
            activeSessionId:
              s.activeSessionId === id
                ? sessions[0]?.id ?? null
                : s.activeSessionId,
          };
        }),

      addMessage: (sessionId, message) =>
        set((s) => ({
          sessions: s.sessions.map((session) => {
            if (session.id !== sessionId) return session;
            const newMsg: Message = {
              ...message,
              id: generateId(),
              timestamp: new Date(),
            };
            const updatedMessages = [...session.messages, newMsg];
            return {
              ...session,
              messages: updatedMessages,
              title:
                session.messages.length === 0 && message.role === "user"
                  ? message.content.slice(0, 40)
                  : session.title,
              updatedAt: new Date(),
            };
          }),
        })),

      setCurrentMode: (mode) => set({ currentMode: mode }),
      setLoading: (loading) => set({ isLoading: loading }),

      toggleGraphViewer: (message) =>
        set((s) => ({
          isGraphViewerOpen: message ? true : !s.isGraphViewerOpen,
          selectedMessage: message ?? s.selectedMessage,
        })),

      getActiveSession: () => {
        const { sessions, activeSessionId } = get();
        return sessions.find((s) => s.id === activeSessionId) ?? null;
      },

      clearAllSessions: () =>
        set({ sessions: [], activeSessionId: null }),
    }),
    {
      name: "cskg-chat-store",
      partialize: (s) => ({ sessions: s.sessions, currentMode: s.currentMode }),
    }
  )
);