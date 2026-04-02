import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { formatDistanceToNow, format } from "date-fns";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: string | Date): string {
  return format(new Date(date), "MMM d, yyyy HH:mm");
}

export function formatRelativeTime(date: string | Date): string {
  return formatDistanceToNow(new Date(date), { addSuffix: true });
}

export function severityColor(severity: string): string {
  const map: Record<string, string> = {
    CRITICAL: "bg-severity-critical/20 text-severity-critical border-severity-critical/30",
    HIGH: "bg-severity-high/20 text-severity-high border-severity-high/30",
    MEDIUM: "bg-severity-medium/20 text-severity-medium border-severity-medium/30",
    LOW: "bg-severity-low/20 text-severity-low border-severity-low/30",
  };
  return map[severity?.toUpperCase()] ?? "bg-zinc-800 text-zinc-400 border-zinc-700";
}

export function severityDot(severity: string): string {
  const map: Record<string, string> = {
    CRITICAL: "bg-severity-critical",
    HIGH: "bg-severity-high",
    MEDIUM: "bg-severity-medium",
    LOW: "bg-severity-low",
  };
  return map[severity?.toUpperCase()] ?? "bg-zinc-500";
}

export const severityOrder: Record<string, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3,
};

export function riskScoreColor(score: number): string {
  if (score >= 8) return "text-severity-critical";
  if (score >= 6) return "text-severity-high";
  if (score >= 4) return "text-severity-medium";
  return "text-severity-low";
}

export function statusColor(status: string): string {
  const map: Record<string, string> = {
    connected: "bg-zinc-700 text-zinc-300",
    scanning: "bg-blue-500/20 text-blue-400",
    protected: "bg-emerald-500/20 text-emerald-400",
    at_risk: "bg-yellow-500/20 text-yellow-400",
    error: "bg-red-500/20 text-red-400",
    open: "bg-red-500/20 text-red-400",
    fixing: "bg-yellow-500/20 text-yellow-400",
    fixed: "bg-emerald-500/20 text-emerald-400",
    verified: "bg-emerald-500/20 text-emerald-400",
    wont_fix: "bg-zinc-700 text-zinc-400",
    false_positive: "bg-zinc-700 text-zinc-400",
  };
  return map[status] ?? "bg-zinc-700 text-zinc-300";
}

export function truncate(str: string, len: number): string {
  if (str.length <= len) return str;
  return str.slice(0, len) + "...";
}
