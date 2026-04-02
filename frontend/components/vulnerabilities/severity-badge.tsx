import { cn } from "@/lib/utils";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

const severityConfig: Record<Severity, { bg: string; text: string; ring: string }> = {
  CRITICAL: {
    bg: "bg-red-500/15",
    text: "text-[#EF4444]",
    ring: "ring-red-500/30",
  },
  HIGH: {
    bg: "bg-orange-500/15",
    text: "text-[#F97316]",
    ring: "ring-orange-500/30",
  },
  MEDIUM: {
    bg: "bg-yellow-500/15",
    text: "text-[#EAB308]",
    ring: "ring-yellow-500/30",
  },
  LOW: {
    bg: "bg-blue-500/15",
    text: "text-[#3B82F6]",
    ring: "ring-blue-500/30",
  },
};

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const config = severityConfig[severity];

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-bold uppercase ring-1 ring-inset",
        config.bg,
        config.text,
        config.ring,
        className
      )}
    >
      {severity}
    </span>
  );
}

export function SeverityDot({ severity }: { severity: Severity }) {
  const colors: Record<Severity, string> = {
    CRITICAL: "bg-[#EF4444]",
    HIGH: "bg-[#F97316]",
    MEDIUM: "bg-[#EAB308]",
    LOW: "bg-[#3B82F6]",
  };

  return (
    <span
      className={cn("inline-block h-2 w-2 rounded-full", colors[severity])}
    />
  );
}
