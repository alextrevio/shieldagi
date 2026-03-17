import { cn } from "@/lib/utils";

interface ThreatLevelGaugeProps {
  level: "CLEAR" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  openVulns: number;
  platformCount: number;
}

const levels = ["CLEAR", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
const levelColors: Record<string, string> = {
  CLEAR: "text-emerald-400",
  LOW: "text-blue-400",
  MEDIUM: "text-yellow-400",
  HIGH: "text-orange-400",
  CRITICAL: "text-red-400",
};
const barColors: Record<string, string> = {
  CLEAR: "bg-emerald-500",
  LOW: "bg-blue-500",
  MEDIUM: "bg-yellow-500",
  HIGH: "bg-orange-500",
  CRITICAL: "bg-red-500",
};

export function ThreatLevelGauge({ level, openVulns, platformCount }: ThreatLevelGaugeProps) {
  const idx = levels.indexOf(level);
  const pct = ((idx + 1) / levels.length) * 100;

  return (
    <div className="rounded-lg border border-border bg-surface-raised p-6">
      <p className="text-xs text-zinc-500 uppercase tracking-wider mb-4">Threat Level</p>
      <div className="flex items-end gap-4 mb-4">
        <span className={cn("text-4xl font-bold", levelColors[level])}>{level}</span>
      </div>
      <div className="h-2 w-full rounded-full bg-zinc-800 overflow-hidden mb-3">
        <div className={cn("h-full rounded-full transition-all duration-700", barColors[level])} style={{ width: `${pct}%` }} />
      </div>
      <p className="text-xs text-zinc-500">
        Based on {openVulns} open vulnerabilities across {platformCount} platforms
      </p>
    </div>
  );
}
