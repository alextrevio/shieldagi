import { createClient } from "@/lib/supabase/server";
import { redirect, notFound } from "next/navigation";
import Link from "next/link";
import {
  VulnDetail,
  type VulnerabilityDetail,
} from "@/components/vulnerabilities/vuln-detail";
import {
  VulnTimeline,
  buildTimelineSteps,
} from "@/components/vulnerabilities/vuln-timeline";
import { ArrowLeft } from "lucide-react";
import { VulnActions } from "./vuln-actions";

export async function generateMetadata({ params }: { params: { id: string } }) {
  return { title: `Vulnerability ${params.id} | ShieldAGI` };
}

export default async function VulnerabilityDetailPage({
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

  const { data: vuln, error } = await supabase
    .from("vulnerabilities")
    .select(
      `
      id,
      shield_id,
      severity,
      cvss_score,
      title,
      description,
      category,
      file,
      start_line,
      end_line,
      affected_code,
      proof_of_concept,
      endpoint,
      status,
      remediation_pr_url,
      created_at,
      analyzed_at,
      fix_generated_at,
      fix_applied_at,
      verified_at,
      scan_id,
      scans!inner (
        id,
        platforms!inner (
          name,
          user_id
        )
      )
    `
    )
    .eq("id", params.id)
    .eq("scans.platforms.user_id", user.id)
    .single();

  if (!vuln) {
    notFound();
  }

  const platform = (vuln as any).scans.platforms;

  const vulnerability: VulnerabilityDetail = {
    id: vuln.id,
    shield_id: vuln.shield_id,
    severity: vuln.severity,
    cvss_score: vuln.cvss_score ?? 0,
    title: vuln.title,
    description: vuln.description ?? "",
    category: vuln.category,
    file: vuln.file,
    start_line: vuln.start_line ?? 1,
    end_line: vuln.end_line ?? 1,
    affected_code: vuln.affected_code ?? "",
    proof_of_concept: vuln.proof_of_concept,
    endpoint: vuln.endpoint,
    status: vuln.status,
    remediation_pr_url: vuln.remediation_pr_url,
    platform_name: platform.name,
    scan_id: vuln.scan_id,
  };

  const timelineSteps = buildTimelineSteps(vuln.status, {
    detected: vuln.created_at,
    analyzed: vuln.analyzed_at,
    fix_generated: vuln.fix_generated_at,
    fix_applied: vuln.fix_applied_at,
    verified: vuln.verified_at,
  });

  return (
    <div className="min-h-screen bg-[#0A0A0B]">
      <div className="mx-auto max-w-6xl px-6 py-8">
        {/* Back nav */}
        <Link
          href="/vulnerabilities"
          className="mb-6 inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          All Vulnerabilities
        </Link>

        <div className="grid gap-6 lg:grid-cols-[1fr_300px]">
          {/* Main content */}
          <div className="space-y-6">
            <VulnDetail vulnerability={vulnerability} />
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            <VulnTimeline steps={timelineSteps} />
            <VulnActions vulnId={vuln.id} currentStatus={vuln.status} />
          </div>
        </div>
      </div>
    </div>
  );
}
