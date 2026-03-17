"use client";

import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { createClient } from "@/lib/supabase/client";
import { Check } from "lucide-react";

interface ScanProgressProps {
  scanId: string;
  initialStatus: string;
  initialProgress: number;
}

const phases = [
  { key: "recon", label: "Recon" },
  { key: "audit", label: "Audit" },
  { key: "attack", label: "Attack" },
  { key: "report", label: "Report" },
] as const;

type Phase = (typeof phases)[number]["key"];

function getPhaseFromProgress(progress: number): number {
  if (progress < 25) return 0;
  if (progress < 50) return 1;
  if (progress < 75) return 2;
  return 3;
}

function getPhaseStatus(
  phaseIndex: number,
  activePhase: number,
  scanStatus: string
): "completed" | "active" | "pending" {
  if (scanStatus === "completed") return "completed";
  if (phaseIndex < activePhase) return "completed";
  if (phaseIndex === activePhase) return "active";
  return "pending";
}

export function ScanProgress({
  scanId,
  initialStatus,
  initialProgress,
}: ScanProgressProps) {
  const [status, setStatus] = useState(initialStatus);
  const [progress, setProgress] = useState(initialProgress);

  useEffect(() => {
    const supabase = createClient();

    const channel = supabase
      .channel(`scan-progress-${scanId}`)
      .on(
        "postgres_changes",
        {
          event: "UPDATE",
          schema: "public",
          table: "scans",
          filter: `id=eq.${scanId}`,
        },
        (payload) => {
          const updated = payload.new as { status: string; progress: number };
          setStatus(updated.status);
          setProgress(updated.progress);
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [scanId]);

  const activePhase = getPhaseFromProgress(progress);

  return (
    <div className="rounded-lg border border-[#1F1F22] bg-[#141415] p-6">
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-sm font-medium text-zinc-100">Scan Progress</h3>
        <span className="font-mono text-sm text-zinc-300">{progress}%</span>
      </div>

      {/* Phase indicators */}
      <div className="relative flex items-center justify-between">
        {/* Connecting line */}
        <div className="absolute left-6 right-6 top-4 h-0.5 bg-zinc-800" />
        <div
          className="absolute left-6 top-4 h-0.5 bg-blue-500 transition-all duration-700"
          style={{
            width: `calc(${(activePhase / (phases.length - 1)) * 100}% - 48px + ${status === "completed" ? "48px" : "0px"})`,
          }}
        />

        {phases.map((phase, index) => {
          const phaseStatus = getPhaseStatus(index, activePhase, status);

          return (
            <div
              key={phase.key}
              className="relative z-10 flex flex-col items-center gap-2"
            >
              {/* Circle */}
              <div
                className={cn(
                  "flex h-8 w-8 items-center justify-center rounded-full border-2 transition-all duration-300",
                  phaseStatus === "completed" &&
                    "border-emerald-500 bg-emerald-500/20",
                  phaseStatus === "active" &&
                    "border-blue-500 bg-blue-500/20",
                  phaseStatus === "pending" &&
                    "border-zinc-700 bg-zinc-900"
                )}
              >
                {phaseStatus === "completed" ? (
                  <Check className="h-4 w-4 text-emerald-400" />
                ) : phaseStatus === "active" ? (
                  <div className="relative">
                    <div className="h-2 w-2 rounded-full bg-blue-400" />
                    <div className="absolute inset-0 h-2 w-2 animate-ping rounded-full bg-blue-400" />
                  </div>
                ) : (
                  <div className="h-2 w-2 rounded-full bg-zinc-600" />
                )}
              </div>

              {/* Label */}
              <span
                className={cn(
                  "text-xs font-medium",
                  phaseStatus === "completed" && "text-emerald-400",
                  phaseStatus === "active" && "text-blue-400",
                  phaseStatus === "pending" && "text-zinc-600"
                )}
              >
                {phase.label}
              </span>
            </div>
          );
        })}
      </div>

      {/* Overall progress bar */}
      <div className="mt-6">
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-zinc-800">
          <div
            className={cn(
              "h-full rounded-full transition-all duration-700",
              status === "completed" ? "bg-emerald-500" : "bg-blue-500"
            )}
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {status === "completed" && (
        <p className="mt-3 text-center text-xs text-emerald-400">
          Scan completed successfully
        </p>
      )}
      {status === "failed" && (
        <p className="mt-3 text-center text-xs text-red-400">
          Scan failed
        </p>
      )}
    </div>
  );
}
