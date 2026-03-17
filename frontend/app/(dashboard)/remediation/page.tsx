import { createClient } from "@/lib/supabase/server";
import { redirect } from "next/navigation";
import { PRCard, type Remediation } from "@/components/remediation/pr-card";
import { GitPullRequest, Clock, GitMerge, Bug } from "lucide-react";

export const metadata = {
  title: "Remediations | ShieldAGI",
};

async function getRemediations() {
  const supabase = await createClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) redirect("/login");

  // Fetch platforms owned by user, then remediations for those platforms
  const { data: platforms } = await supabase
    .from("platforms")
    .select("id")
    .eq("user_id", user.id);

  if (!platforms || platforms.length === 0) {
    return [];
  }

  const platformIds = platforms.map((p) => p.id);

  const { data: remediations, error } = await supabase
    .from("remediation_prs")
    .select("*")
    .in("platform_id", platformIds)
    .order("created_at", { ascending: false });

  if (error) {
    console.error("Error fetching remediations:", error);
    return [];
  }

  return (remediations ?? []) as Remediation[];
}

export default async function RemediationsPage() {
  const remediations = await getRemediations();

  const pending = remediations.filter(
    (r) =>
      r.status === "generating" ||
      r.status === "pending_review" ||
      r.status === "approved"
  );
  const completed = remediations.filter(
    (r) =>
      r.status === "merged" ||
      r.status === "rejected" ||
      r.status === "failed"
  );

  const totalPRs = remediations.length;
  const pendingCount = pending.length;
  const mergedCount = remediations.filter((r) => r.status === "merged").length;
  const totalFixesCount = remediations.reduce(
    (sum, r) => sum + r.fixes_count,
    0
  );

  const stats = [
    {
      label: "Total PRs",
      value: totalPRs,
      icon: GitPullRequest,
      color: "text-zinc-100",
    },
    {
      label: "Pending",
      value: pendingCount,
      icon: Clock,
      color: "text-yellow-400",
    },
    {
      label: "Merged",
      value: mergedCount,
      icon: GitMerge,
      color: "text-purple-400",
    },
    {
      label: "Vulns Fixed",
      value: totalFixesCount,
      icon: Bug,
      color: "text-green-400",
    },
  ];

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold text-zinc-100">Remediations</h1>
        <p className="mt-1 text-sm text-zinc-500">
          AI-generated pull requests fixing discovered vulnerabilities.
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {stats.map((stat) => (
          <div
            key={stat.label}
            className="rounded-lg border border-[#1F1F22] bg-[#141415] p-4"
          >
            <div className="flex items-center gap-2 mb-2">
              <stat.icon className="h-4 w-4 text-zinc-500" />
              <span className="text-xs text-zinc-500">{stat.label}</span>
            </div>
            <p className={`text-2xl font-semibold ${stat.color}`}>
              {stat.value}
            </p>
          </div>
        ))}
      </div>

      {/* Pending Review Section */}
      {pending.length > 0 && (
        <div>
          <h2 className="text-lg font-medium text-zinc-200 mb-4 flex items-center gap-2">
            <Clock className="h-4 w-4 text-yellow-400" />
            Pending Review
            <span className="ml-1 inline-flex items-center rounded-full bg-yellow-500/10 border border-yellow-500/20 px-2 py-0.5 text-xs font-medium text-yellow-400">
              {pending.length}
            </span>
          </h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {pending.map((remediation) => (
              <PRCard key={remediation.id} remediation={remediation} />
            ))}
          </div>
        </div>
      )}

      {/* Completed Section */}
      <div>
        <h2 className="text-lg font-medium text-zinc-200 mb-4 flex items-center gap-2">
          <GitMerge className="h-4 w-4 text-purple-400" />
          Completed
          {completed.length > 0 && (
            <span className="ml-1 inline-flex items-center rounded-full bg-zinc-500/10 border border-zinc-500/20 px-2 py-0.5 text-xs font-medium text-zinc-400">
              {completed.length}
            </span>
          )}
        </h2>
        {completed.length > 0 ? (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {completed.map((remediation) => (
              <PRCard key={remediation.id} remediation={remediation} />
            ))}
          </div>
        ) : (
          <div className="rounded-lg border border-[#1F1F22] bg-[#141415] p-12 text-center">
            <GitMerge className="mx-auto h-8 w-8 text-zinc-600 mb-3" />
            <p className="text-sm text-zinc-500">
              No completed remediations yet.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
