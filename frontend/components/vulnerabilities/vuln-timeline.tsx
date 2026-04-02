import { cn } from "@/lib/utils";
import { Check, Circle, Loader2 } from "lucide-react";

interface TimelineStep {
  key: string;
  label: string;
  timestamp: string | null;
  status: "complete" | "active" | "pending";
}

interface VulnTimelineProps {
  steps: TimelineStep[];
}

const defaultSteps: Omit<TimelineStep, "timestamp" | "status">[] = [
  { key: "detected", label: "Detected" },
  { key: "analyzed", label: "Analyzed" },
  { key: "fix_generated", label: "Fix Generated" },
  { key: "fix_applied", label: "Fix Applied" },
  { key: "verified", label: "Verified" },
];

export function buildTimelineSteps(
  vulnStatus: string,
  timestamps: Record<string, string | null>
): TimelineStep[] {
  const statusIndex: Record<string, number> = {
    open: 0,
    analyzing: 1,
    fix_generating: 2,
    fixing: 3,
    fixed: 4,
    verified: 5,
  };

  const currentIndex = statusIndex[vulnStatus] ?? 0;

  return defaultSteps.map((step, index) => {
    let status: TimelineStep["status"] = "pending";
    if (index < currentIndex) {
      status = "complete";
    } else if (index === currentIndex) {
      status = currentIndex === defaultSteps.length ? "complete" : "active";
    }

    return {
      ...step,
      timestamp: timestamps[step.key] ?? null,
      status,
    };
  });
}

function formatTimestamp(ts: string | null): string {
  if (!ts) return "";
  const date = new Date(ts);
  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function VulnTimeline({ steps }: VulnTimelineProps) {
  return (
    <div className="rounded-lg border border-[#1F1F22] bg-[#141415] p-6">
      <h3 className="mb-6 text-sm font-medium text-zinc-100">
        Vulnerability Lifecycle
      </h3>

      <div className="relative ml-3">
        {/* Connecting vertical line */}
        <div className="absolute left-[7px] top-2 h-[calc(100%-16px)] w-0.5 bg-zinc-800" />

        <div className="space-y-6">
          {steps.map((step, index) => (
            <div key={step.key} className="relative flex items-start gap-4">
              {/* Icon */}
              <div className="relative z-10">
                {step.status === "complete" ? (
                  <div className="flex h-4 w-4 items-center justify-center rounded-full bg-emerald-500">
                    <Check className="h-2.5 w-2.5 text-white" />
                  </div>
                ) : step.status === "active" ? (
                  <div className="relative flex h-4 w-4 items-center justify-center">
                    <div className="absolute h-4 w-4 animate-ping rounded-full bg-blue-500/40" />
                    <div className="h-4 w-4 rounded-full border-2 border-blue-500 bg-blue-500/20" />
                  </div>
                ) : (
                  <div className="h-4 w-4 rounded-full border-2 border-zinc-700 bg-zinc-900" />
                )}
              </div>

              {/* Content */}
              <div className="-mt-0.5 flex-1">
                <p
                  className={cn(
                    "text-sm font-medium",
                    step.status === "complete" && "text-emerald-400",
                    step.status === "active" && "text-blue-400",
                    step.status === "pending" && "text-zinc-600"
                  )}
                >
                  {step.label}
                </p>
                {step.timestamp && (
                  <p className="mt-0.5 text-xs text-zinc-500">
                    {formatTimestamp(step.timestamp)}
                  </p>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
