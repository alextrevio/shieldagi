"use client";

import Link from "next/link";
import { cn, formatRelativeTime, truncate, severityColor } from "@/lib/utils";
import {
  AlertTriangle,
  Shield,
  Zap,
  CheckCircle2,
  XCircle,
} from "lucide-react";

export interface Incident {
  id: string;
  severity: string;
  status: "active" | "contained" | "mitigated" | "resolved";
  title: string;
  attack_type: string;
  source_ips: string[];
  created_at: string;
  auto_patched: boolean;
}

const incidentStatusConfig: Record<
  Incident["status"],
  { label: string; color: string; bgColor: string; pulse?: boolean }
> = {
  active: {
    label: "Active",
    color: "text-red-400",
    bgColor: "bg-red-500/10 border-red-500/20",
    pulse: true,
  },
  contained: {
    label: "Contained",
    color: "text-orange-400",
    bgColor: "bg-orange-500/10 border-orange-500/20",
  },
  mitigated: {
    label: "Mitigated",
    color: "text-yellow-400",
    bgColor: "bg-yellow-500/10 border-yellow-500/20",
  },
  resolved: {
    label: "Resolved",
    color: "text-green-400",
    bgColor: "bg-green-500/10 border-green-500/20",
  },
};

interface IncidentCardProps {
  incident: Incident;
}

export function IncidentCard({ incident }: IncidentCardProps) {
  const statusCfg = incidentStatusConfig[incident.status];
  const ipsDisplay =
    incident.source_ips.length > 3
      ? `${incident.source_ips.slice(0, 3).join(", ")} +${incident.source_ips.length - 3}`
      : incident.source_ips.join(", ");

  return (
    <Link href="/sentinel/incidents">
      <div
        className={cn(
          "group rounded-lg border border-[#1F1F22] bg-[#141415] p-5",
          "hover:border-[#2A2A2E] hover:bg-[#181819] transition-all duration-200",
          "cursor-pointer"
        )}
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-2">
            <span
              className={cn(
                "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium",
                severityColor(incident.severity)
              )}
            >
              {incident.severity}
            </span>
            <span
              className={cn(
                "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium",
                statusCfg.bgColor,
                statusCfg.color
              )}
            >
              {statusCfg.pulse && (
                <span className="h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse" />
              )}
              {statusCfg.label}
            </span>
          </div>
          <span className="text-xs text-zinc-600 shrink-0">
            {formatRelativeTime(incident.created_at)}
          </span>
        </div>

        {/* Title */}
        <h3 className="text-sm font-medium text-zinc-100 mb-2 line-clamp-2">
          {incident.title}
        </h3>

        {/* Details */}
        <div className="flex items-center gap-3 text-xs text-zinc-500 mb-3">
          <span className="flex items-center gap-1">
            <AlertTriangle className="h-3.5 w-3.5" />
            {incident.attack_type}
          </span>
        </div>

        {/* Source IPs */}
        {incident.source_ips.length > 0 && (
          <div className="text-xs text-zinc-600 font-mono mb-3">
            {ipsDisplay}
          </div>
        )}

        {/* Footer */}
        <div className="flex items-center gap-2">
          {incident.auto_patched && (
            <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 text-xs font-medium text-emerald-400">
              <Zap className="h-3 w-3" />
              Auto-patched
            </span>
          )}
        </div>
      </div>
    </Link>
  );
}
