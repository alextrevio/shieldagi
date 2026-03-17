import { createClient } from "@/lib/supabase/server";
import { redirect, notFound } from "next/navigation";
import Link from "next/link";
import { cn } from "@/lib/utils";
import { ScanProgress } from "@/components/scans/scan-progress";
import { ScanResults, type ScanVulnerability } from "@/components/scans/scan-results";
import { SeverityBadge } from "@/components/vulnerabilities/severity-badge";
import {
  ArrowLeft,
  CheckCircle2,
  Clock,
  Loader2,
  AlertCircle,
  Shield,
  Wrench,
} from "lucide-react";
import { RemediateButton } from "./remediate-button";

export async function generateMetadata({ params }: { params: { id: string } }) {
  return { title: `Scan ${params.id} | ShieldAGI` };
}

export default async function ScanDetailPage({
  params,
}: {
  params: { id: string };
}) {
  const supabase = createClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const { data: scan, error } = await supabase
    .from("scans")
    .select(
      `
      id,
      type,
      status,
      progress,
      vulnerability_count,
      risk_score,
      created_at,
      completed_at,
      platforms!inner (
        id,
        name,
        user_id
      )
    `
    )
    .eq("id", params.id)
    .eq("platforms.user_id", user.id)
    .single();

  if (!scan) {
    notFound();
  }

  let vulnerabilities: ScanVulnerability[] = [];
  if (scan.status === "completed") {
    const { data: vulns } = await supabase
      .from("vulnerabilities")
      .select("id, shield_id, severity, category, title, file, exploitable, status")
      .eq("scan_id", scan.id)
      .order("severity", { ascending: true });

    vulnerabilities = (vulns ?? []).map((v: any) => ({
      id: v.id,
      shield_id: v.shield_id,
      severity: v.severity,
      category: v.category,
      title: v.title,
      file: v.file,
      exploitable: v.exploitable ?? false,
      status: v.status,
    }));
  }

  const platform = (scan as any).platforms;
  const vulnCount = (scan.vulnerability_count as any) ?? {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  const totalVulns =
    vulnCount.critical + vulnCount.high + vulnCount.medium + vulnCount.low;

  const statusConfig: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
    queued: {
      label: "Queued",
      color: "text-zinc-400",
      icon: <Clock className="h-4 w-4" />,
    },
    running: {
      label: "Running",
      color: "text-blue-400",
      icon: <Loader2 className="h-4 w-4 animate-spin" />,
    },
    completed: {
      label: "Completed",
      color: "text-emerald-400",
      icon: <CheckCircle2 className="h-4 w-4" />,
    },
    failed: {
      label: "Failed",
      color: "text-red-400",
      icon: <AlertCircle className="h-4 w-4" />,
    },
    cancelled: {
      label: "Cancelled",
      color: "text-zinc-500",
      icon: <AlertCircle className="h-4 w-4" />,
    },
  };

  const typeLabels: Record<string, string> = {
    full: "Full Scan",
    quick: "Quick Scan",
    targeted: "Targeted Scan",
    remediation: "Remediation Scan",
  };

  const statusInfo = statusConfig[scan.status] ?? statusConfig.queued;

  const duration = (() => {
    const start = new Date(scan.created_at);
    const end = scan.completed_at ? new Date(scan.completed_at) : new Date();
    const diffMs = end.getTime() - start.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours > 0) return `${diffHours}h ${diffMins % 60}m`;
    return `${diffMins}m`;
  })();

  return (
    <div className="min-h-screen bg-[#0A0A0B]">
      <div className="mx-auto max-w-6xl px-6 py-8">
        {/* Back nav */}
        <Link
          href="/scans"
          className="mb-6 inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          All Scans
        </Link>

        {/* Header */}
        <div className="mb-8 rounded-lg border border-[#1F1F22] bg-[#141415] p-6">
          <div className="flex items-start justify-between">
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-zinc-800">
                  <Shield className="h-5 w-5 text-zinc-400" />
                </div>
                <div>
                  <h1 className="text-xl font-semibold text-zinc-100">
                    {platform.name}
                  </h1>
                  <div className="mt-0.5 flex items-center gap-3 text-xs text-zinc-500">
                    <span>{typeLabels[scan.type] ?? scan.type}</span>
                    <span>
                      Started{" "}
                      {new Date(scan.created_at).toLocaleDateString("en-US", {
                        month: "short",
                        day: "numeric",
                        year: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </span>
                    <span>{duration}</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5">
                {statusInfo.icon}
                <span
                  className={cn("text-sm font-medium", statusInfo.color)}
                >
                  {statusInfo.label}
                </span>
              </div>

              {scan.risk_score != null && (
                <div className="ml-4 flex flex-col items-center rounded-lg border border-[#1F1F22] bg-zinc-900 px-4 py-2">
                  <span
                    className={cn(
                      "text-2xl font-bold",
                      scan.risk_score >= 80
                        ? "text-[#EF4444]"
                        : scan.risk_score >= 60
                          ? "text-[#F97316]"
                          : scan.risk_score >= 40
                            ? "text-[#EAB308]"
                            : "text-[#3B82F6]"
                    )}
                  >
                    {scan.risk_score}
                  </span>
                  <span className="text-xs text-zinc-500">Risk Score</span>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Progress (if running) */}
        {(scan.status === "running" || scan.status === "queued") && (
          <div className="mb-8">
            <ScanProgress
              scanId={scan.id}
              initialStatus={scan.status}
              initialProgress={scan.progress ?? 0}
            />
          </div>
        )}

        {/* Results (if completed) */}
        {scan.status === "completed" && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-medium text-zinc-100">Results</h2>
              {totalVulns > 0 && (
                <RemediateButton scanId={scan.id} platformId={platform.id} />
              )}
            </div>
            <ScanResults vulnerabilities={vulnerabilities} />
          </div>
        )}

        {/* Failed message */}
        {scan.status === "failed" && (
          <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-6 text-center">
            <AlertCircle className="mx-auto h-8 w-8 text-red-400" />
            <p className="mt-3 text-sm text-zinc-300">
              This scan encountered an error and could not be completed.
            </p>
            <p className="mt-1 text-xs text-zinc-500">
              Try running the scan again or contact support if the issue
              persists.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
