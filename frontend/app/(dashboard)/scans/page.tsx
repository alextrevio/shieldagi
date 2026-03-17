import { createClient } from "@/lib/supabase/server";
import { redirect } from "next/navigation";
import Link from "next/link";
import { cn } from "@/lib/utils";
import { SeverityDot } from "@/components/vulnerabilities/severity-badge";
import { ScanCard, type Scan } from "@/components/scans/scan-card";
import { Plus, Search } from "lucide-react";
import { ScansFilterClient } from "./scans-filter-client";

export const metadata = {
  title: "Scans | ShieldAGI",
};

export default async function ScansPage({
  searchParams,
}: {
  searchParams: { status?: string };
}) {
  const supabase = createClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const query = supabase
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
        name,
        user_id
      )
    `
    )
    .eq("platforms.user_id", user.id)
    .order("created_at", { ascending: false });

  if (searchParams.status && searchParams.status !== "all") {
    query.eq("status", searchParams.status);
  }

  const { data: scans, error } = await query;

  const formattedScans: Scan[] = (scans ?? []).map((scan: any) => ({
    id: scan.id,
    platform_name: scan.platforms.name,
    type: scan.type,
    status: scan.status,
    progress: scan.progress ?? 0,
    vulnerability_count: scan.vulnerability_count ?? {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    },
    risk_score: scan.risk_score,
    created_at: scan.created_at,
    completed_at: scan.completed_at,
  }));

  const runningScans = formattedScans.filter((s) => s.status === "running");
  const otherScans = formattedScans.filter((s) => s.status !== "running");

  return (
    <div className="min-h-screen bg-[#0A0A0B]">
      <div className="mx-auto max-w-6xl px-6 py-8">
        {/* Header */}
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-zinc-100">Scans</h1>
            <p className="mt-1 text-sm text-zinc-500">
              Monitor and manage security scans across your platforms.
            </p>
          </div>
          <Link
            href="/scans/new"
            className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-500"
          >
            <Plus className="h-4 w-4" />
            New Scan
          </Link>
        </div>

        {/* Status filter */}
        <ScansFilterClient currentStatus={searchParams.status ?? "all"} />

        {/* Running scans */}
        {runningScans.length > 0 && (
          <div className="mb-6">
            <h2 className="mb-3 text-xs font-medium uppercase tracking-wider text-zinc-500">
              Running
            </h2>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {runningScans.map((scan) => (
                <ScanCard key={scan.id} scan={scan} />
              ))}
            </div>
          </div>
        )}

        {/* All scans table */}
        <div className="rounded-lg border border-[#1F1F22] bg-[#141415]">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1F1F22]">
                <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500">
                  Platform
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500">
                  Type
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500">
                  Status
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500">
                  Vulns
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500">
                  Risk Score
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500">
                  Started
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500">
                  Duration
                </th>
              </tr>
            </thead>
            <tbody>
              {otherScans.map((scan) => {
                const totalVulns =
                  scan.vulnerability_count.critical +
                  scan.vulnerability_count.high +
                  scan.vulnerability_count.medium +
                  scan.vulnerability_count.low;

                const duration = (() => {
                  const start = new Date(scan.created_at);
                  const end = scan.completed_at
                    ? new Date(scan.completed_at)
                    : new Date();
                  const diffMs = end.getTime() - start.getTime();
                  const diffMins = Math.floor(diffMs / 60000);
                  const diffHours = Math.floor(diffMins / 60);
                  if (diffHours > 0) return `${diffHours}h ${diffMins % 60}m`;
                  return `${diffMins}m`;
                })();

                const statusColor: Record<string, string> = {
                  queued: "text-zinc-400",
                  running: "text-blue-400",
                  completed: "text-emerald-400",
                  failed: "text-red-400",
                  cancelled: "text-zinc-500",
                };

                const typeLabel: Record<string, string> = {
                  full: "Full",
                  quick: "Quick",
                  targeted: "Targeted",
                  remediation: "Remediation",
                };

                return (
                  <tr
                    key={scan.id}
                    className="border-b border-[#1F1F22] transition-colors hover:bg-zinc-900/50"
                  >
                    <td className="px-4 py-3">
                      <Link
                        href={`/scans/${scan.id}`}
                        className="text-sm font-medium text-zinc-200 hover:text-white"
                      >
                        {scan.platform_name}
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center rounded-full border border-zinc-800 bg-zinc-900 px-2 py-0.5 text-xs text-zinc-400">
                        {typeLabel[scan.type] ?? scan.type}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          "text-xs font-medium capitalize",
                          statusColor[scan.status] ?? "text-zinc-400"
                        )}
                      >
                        {scan.status}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {scan.status === "completed" ? (
                        <div className="flex items-center gap-2">
                          {scan.vulnerability_count.critical > 0 && (
                            <span className="flex items-center gap-1">
                              <SeverityDot severity="CRITICAL" />
                              <span className="text-xs text-zinc-400">
                                {scan.vulnerability_count.critical}
                              </span>
                            </span>
                          )}
                          {scan.vulnerability_count.high > 0 && (
                            <span className="flex items-center gap-1">
                              <SeverityDot severity="HIGH" />
                              <span className="text-xs text-zinc-400">
                                {scan.vulnerability_count.high}
                              </span>
                            </span>
                          )}
                          {totalVulns === 0 && (
                            <span className="text-xs text-zinc-500">0</span>
                          )}
                          {totalVulns > 0 &&
                            scan.vulnerability_count.critical === 0 &&
                            scan.vulnerability_count.high === 0 && (
                              <span className="text-xs text-zinc-400">
                                {totalVulns}
                              </span>
                            )}
                        </div>
                      ) : (
                        <span className="text-xs text-zinc-600">-</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {scan.risk_score != null ? (
                        <span
                          className={cn(
                            "font-mono text-sm font-medium",
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
                      ) : (
                        <span className="text-xs text-zinc-600">-</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-zinc-500">
                      {new Date(scan.created_at).toLocaleDateString("en-US", {
                        month: "short",
                        day: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </td>
                    <td className="px-4 py-3 text-xs text-zinc-500">
                      {duration}
                    </td>
                  </tr>
                );
              })}
              {otherScans.length === 0 && runningScans.length === 0 && (
                <tr>
                  <td
                    colSpan={7}
                    className="px-4 py-12 text-center text-sm text-zinc-500"
                  >
                    No scans found. Start a new scan to begin.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
