"use client";

import Link from "next/link";
import { cn } from "@/lib/utils";
import { SeverityDot } from "@/components/vulnerabilities/severity-badge";
import {
  Clock,
  CheckCircle2,
  AlertCircle,
  Loader2,
  Shield,
} from "lucide-react";

export interface Scan {
  id: string;
  platform_name: string;
  type: "full" | "quick" | "targeted" | "remediation";
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  progress: number;
  vulnerability_count: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  risk_score?: number;
  created_at: string;
  completed_at: string | null;
}

interface ScanCardProps {
  scan: Scan;
}

const statusConfig: Record<
  Scan["status"],
  { label: string; color: string; icon: React.ReactNode }
> = {
  queued: {
    label: "Queued",
    color: "text-zinc-400",
    icon: <Clock className="h-3.5 w-3.5" />,
  },
  running: {
    label: "Running",
    color: "text-blue-400",
    icon: <Loader2 className="h-3.5 w-3.5 animate-spin" />,
  },
  completed: {
    label: "Completed",
    color: "text-emerald-400",
    icon: <CheckCircle2 className="h-3.5 w-3.5" />,
  },
  failed: {
    label: "Failed",
    color: "text-red-400",
    icon: <AlertCircle className="h-3.5 w-3.5" />,
  },
  cancelled: {
    label: "Cancelled",
    color: "text-zinc-500",
    icon: <AlertCircle className="h-3.5 w-3.5" />,
  },
};

const typeLabels: Record<Scan["type"], string> = {
  full: "Full Scan",
  quick: "Quick Scan",
  targeted: "Targeted",
  remediation: "Remediation",
};

function formatDuration(start: string, end: string | null): string {
  const startDate = new Date(start);
  const endDate = end ? new Date(end) : new Date();
  const diffMs = endDate.getTime() - startDate.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);

  if (diffHours > 0) {
    return `${diffHours}h ${diffMins % 60}m`;
  }
  return `${diffMins}m`;
}

function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
}

export function ScanCard({ scan }: ScanCardProps) {
  const status = statusConfig[scan.status];
  const totalVulns =
    scan.vulnerability_count.critical +
    scan.vulnerability_count.high +
    scan.vulnerability_count.medium +
    scan.vulnerability_count.low;

  return (
    <Link href={`/scans/${scan.id}`}>
      <div className="group rounded-lg border border-[#1F1F22] bg-[#141415] p-4 transition-all hover:border-zinc-700 hover:bg-[#1a1a1c]">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-zinc-800">
              <Shield className="h-4 w-4 text-zinc-400" />
            </div>
            <div>
              <h3 className="text-sm font-medium text-zinc-100">
                {scan.platform_name}
              </h3>
              <span className="text-xs text-zinc-500">
                {formatRelativeTime(scan.created_at)}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span
              className={cn(
                "inline-flex items-center rounded-full border border-zinc-800 bg-zinc-900 px-2.5 py-0.5 text-xs font-medium",
                "text-zinc-400"
              )}
            >
              {typeLabels[scan.type]}
            </span>
          </div>
        </div>

        {/* Progress bar for running scans */}
        {scan.status === "running" && (
          <div className="mt-3">
            <div className="flex items-center justify-between text-xs">
              <span className="text-zinc-400">Progress</span>
              <span className="font-mono text-zinc-300">{scan.progress}%</span>
            </div>
            <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-zinc-800">
              <div
                className="h-full rounded-full bg-blue-500 transition-all duration-500"
                style={{ width: `${scan.progress}%` }}
              />
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="mt-3 flex items-center justify-between border-t border-[#1F1F22] pt-3">
          <div className="flex items-center gap-1.5">
            {status.icon}
            <span className={cn("text-xs font-medium", status.color)}>
              {status.label}
            </span>
          </div>

          {scan.status === "completed" && (
            <div className="flex items-center gap-3">
              {scan.vulnerability_count.critical > 0 && (
                <div className="flex items-center gap-1">
                  <SeverityDot severity="CRITICAL" />
                  <span className="text-xs text-zinc-400">
                    {scan.vulnerability_count.critical}
                  </span>
                </div>
              )}
              {scan.vulnerability_count.high > 0 && (
                <div className="flex items-center gap-1">
                  <SeverityDot severity="HIGH" />
                  <span className="text-xs text-zinc-400">
                    {scan.vulnerability_count.high}
                  </span>
                </div>
              )}
              {scan.vulnerability_count.medium > 0 && (
                <div className="flex items-center gap-1">
                  <SeverityDot severity="MEDIUM" />
                  <span className="text-xs text-zinc-400">
                    {scan.vulnerability_count.medium}
                  </span>
                </div>
              )}
              {scan.vulnerability_count.low > 0 && (
                <div className="flex items-center gap-1">
                  <SeverityDot severity="LOW" />
                  <span className="text-xs text-zinc-400">
                    {scan.vulnerability_count.low}
                  </span>
                </div>
              )}
              {totalVulns === 0 && (
                <span className="text-xs text-emerald-400">No issues</span>
              )}
            </div>
          )}

          {(scan.status === "completed" || scan.status === "running") && (
            <span className="text-xs text-zinc-500">
              {formatDuration(scan.created_at, scan.completed_at)}
            </span>
          )}
        </div>
      </div>
    </Link>
  );
}
