import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { AnalysisMode, GraphData, RDFTriple } from "./types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function generateId(): string {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

export function getModeLabel(mode: AnalysisMode): string {
  const labels: Record<AnalysisMode, string> = {
    threat_intelligence: "Threat Intelligence",
    log_analysis: "Security Log Analysis",
    combined: "Combined Analysis",
  };
  return labels[mode];
}

export function getModeDescription(mode: AnalysisMode): string {
  const descriptions: Record<AnalysisMode, string> = {
    threat_intelligence:
      "Analyze malware, CVEs, threat actors using SEPSES CSKG",
    log_analysis: "Parse and analyze security logs for suspicious activity",
    combined:
      "Correlate log events with threat intelligence from CSKG",
  };
  return descriptions[mode];
}

export function getModeColor(mode: AnalysisMode): string {
  const colors: Record<AnalysisMode, string> = {
    threat_intelligence: "text-red-400",
    log_analysis: "text-yellow-400",
    combined: "text-cyan-400",
  };
  return colors[mode];
}

export function getNodeColor(type: string): string {
  const palette: Record<string, string> = {
    Malware: "#ef4444",
    CVE: "#f97316",
    ThreatActor: "#8b5cf6",
    AttackPattern: "#ec4899",
    Vulnerability: "#f59e0b",
    Tool: "#3b82f6",
    Campaign: "#10b981",
    Identity: "#6366f1",
    default: "#6b7280",
  };
  return palette[type] ?? palette.default;
}

export function triplesToGraphData(triples: RDFTriple[]): GraphData {
  const nodeMap = new Map<string, { id: string; label: string; type: string }>();
  const links: GraphData["links"] = [];

  const getLabel = (uri: string) => {
    const parts = uri.split(/[#/]/);
    return parts[parts.length - 1] || uri;
  };

  const inferType = (uri: string): string => {
    const lower = uri.toLowerCase();
    if (lower.includes("malware")) return "Malware";
    if (lower.includes("cve")) return "CVE";
    if (lower.includes("threat") || lower.includes("actor")) return "ThreatActor";
    if (lower.includes("attack")) return "AttackPattern";
    if (lower.includes("vuln")) return "Vulnerability";
    if (lower.includes("tool")) return "Tool";
    if (lower.includes("campaign")) return "Campaign";
    return "default";
  };

  triples.forEach((triple) => {
    if (!nodeMap.has(triple.subject)) {
      nodeMap.set(triple.subject, {
        id: triple.subject,
        label: getLabel(triple.subject),
        type: inferType(triple.subject),
      });
    }
    if (!nodeMap.has(triple.object)) {
      nodeMap.set(triple.object, {
        id: triple.object,
        label: getLabel(triple.object),
        type: inferType(triple.object),
      });
    }
    links.push({
      source: triple.subject,
      target: triple.object,
      label: getLabel(triple.predicate),
    });
  });

  return {
    nodes: Array.from(nodeMap.values()).map((n) => ({
      ...n,
      color: getNodeColor(n.type),
    })),
    links,
  };
}

export function formatTimestamp(date: Date): string {
  return new Intl.DateTimeFormat("id-ID", {
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(date));
}

export function truncateText(text: string, maxLength = 40): string {
  return text.length > maxLength ? text.slice(0, maxLength) + "..." : text;
}