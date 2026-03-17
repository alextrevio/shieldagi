"use client";

import Link from "next/link";
import { cn, formatRelativeTime } from "@/lib/utils";
import {
  ExternalLink,
  GitPullRequest,
  FileCode,
  Bug,
  Shield,
} from "lucide-react";

export type RemediationStatus =
  | "generating"
  | "pending_review"
  | "approved"
  | "merged"
  | "rejected"
  | "failed";

export interface Remediation {
  id: string;
  title: string;
  status: RemediationStatus;
  pr_url: string | null;
  pr_number: number | null;
  fixes_count: number;
  chain_walls_added: boolean;
  files_modified: number;
  created_at: string;
}

const statusConfig: Record<
  RemediationStatus,
  { label: string; color: string; bgColor: string }
> = {
  generating: {
    label: "Generating",
    color: "text-blue-400",
    bgColor: "bg-blue-500/10 border-blue-500/20",
  },
  pending_review: {
    label: "Pending Review",
    color: "text-yellow-400",
    bgColor: "bg-yellow-500/10 border-yellow-500/20",
  },
  approved: {
    label: "Approved",
    color: "text-green-400",
    bgColor: "bg-green-500/10 border-green-500/20",
  },
  merged: {
    label: "Merged",
    color: "text-purple-400",
    bgColor: "bg-purple-500/10 border-purple-500/20",
  },
  rejected: {
    label: "Rejected",
    color: "text-red-400",
    bgColor: "bg-red-500/10 border-red-500/20",
  },
  failed: {
    label: "Failed",
    color: "text-red-400",
    bgColor: "bg-red-500/10 border-red-500/20",
  },
};

interface PRCardProps {
  remediation: Remediation;
}

export function PRCard({ remediation }: PRCardProps) {
  const status = statusConfig[remediation.status];

  return (
    <Link href={`/remediation/${remediation.id}`}>
      <div
        className={cn(
          "group rounded-lg border border-[#1F1F22] bg-[#141415] p-5",
          "hover:border-[#2A2A2E] hover:bg-[#181819] transition-all duration-200",
          "cursor-pointer"
        )}
      >
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-2 min-w-0">
            <GitPullRequest className="h-4 w-4 text-zinc-400 shrink-0" />
            <h3 className="text-sm font-medium text-zinc-100 truncate">
              {remediation.title}
            </h3>
          </div>
          <span
            className={cn(
              "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium shrink-0",
              status.bgColor,
              status.color
            )}
          >
            {remediation.status === "generating" && (
              <span className="mr-1.5 h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
            )}
            {status.label}
          </span>
        </div>

        <div className="flex items-center gap-4 text-xs text-zinc-500 mb-3">
          <span className="flex items-center gap-1">
            <Bug className="h-3.5 w-3.5" />
            {remediation.fixes_count} fix{remediation.fixes_count !== 1 ? "es" : ""}
          </span>
          <span className="flex items-center gap-1">
            <FileCode className="h-3.5 w-3.5" />
            {remediation.files_modified} file{remediation.files_modified !== 1 ? "s" : ""} modified
          </span>
        </div>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {remediation.chain_walls_added && (
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 text-xs font-medium text-emerald-400">
                <Shield className="h-3 w-3" />
                Chain Walls
              </span>
            )}
          </div>

          <div className="flex items-center gap-3">
            {remediation.pr_url && remediation.pr_number && (
              <span
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  window.open(remediation.pr_url!, "_blank");
                }}
                className="flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
              >
                <ExternalLink className="h-3 w-3" />
                #{remediation.pr_number}
              </span>
            )}
            <span className="text-xs text-zinc-600">
              {formatRelativeTime(remediation.created_at)}
            </span>
          </div>
        </div>
      </div>
    </Link>
  );
}
