import { createClient } from "@/lib/supabase/server";
import { redirect, notFound } from "next/navigation";
import { severityColor } from "@/lib/utils";
import { FixStatus } from "@/components/remediation/fix-status";
import { CodeDiffClient } from "./code-diff-client";
import {
  ExternalLink,
  GitPullRequest,
  Shield,
  Bug,
  FileCode,
  CheckCircle2,
  XCircle,
  ArrowLeft,
} from "lucide-react";
import Link from "next/link";

interface PageProps {
  params: Promise<{ id: string }>;
}

interface DiffBlock {
  filename: string;
  oldCode: string;
  newCode: string;
}

function parseDiffsFromDescription(description: string | null): DiffBlock[] {
  if (!description) return [];

  const diffs: DiffBlock[] = [];
  const diffRegex = /```diff\s*\n(?:---\s+a\/(.+?)\n\+\+\+\s+b\/(.+?)\n)?([\s\S]*?)```/g;
  let match: RegExpExecArray | null;

  while ((match = diffRegex.exec(description)) !== null) {
    const filename = match[2] || match[1] || "unknown";
    const diffContent = match[3];

    const oldLines: string[] = [];
    const newLines: string[] = [];

    for (const line of diffContent.split("\n")) {
      if (line.startsWith("@@")) continue;
      if (line.startsWith("-")) {
        oldLines.push(line.substring(1));
      } else if (line.startsWith("+")) {
        newLines.push(line.substring(1));
      } else {
        const content = line.startsWith(" ") ? line.substring(1) : line;
        oldLines.push(content);
        newLines.push(content);
      }
    }

    diffs.push({
      filename,
      oldCode: oldLines.join("\n"),
      newCode: newLines.join("\n"),
    });
  }

  // Also handle fenced code blocks with filenames as headers
  if (diffs.length === 0) {
    const codeBlockRegex = /###?\s+`?([^\n`]+)`?\s*\n\s*```\w*\n([\s\S]*?)```/g;
    let codeMatch: RegExpExecArray | null;
    while ((codeMatch = codeBlockRegex.exec(description)) !== null) {
      diffs.push({
        filename: codeMatch[1].trim(),
        oldCode: "",
        newCode: codeMatch[2],
      });
    }
  }

  return diffs;
}

async function getRemediation(id: string) {
  const supabase = await createClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) redirect("/login");

  const { data: remediation, error } = await supabase
    .from("remediation_prs")
    .select("*, platforms(name, repo_url)")
    .eq("id", id)
    .single();

  if (error || !remediation) {
    notFound();
  }

  // Fetch vulnerabilities fixed by this PR
  const { data: vulnerabilities } = await supabase
    .from("vulnerabilities")
    .select("id, title, severity, status, cwe_id")
    .eq("remediation_pr_id", id)
    .order("severity", { ascending: true });

  return { remediation, vulnerabilities: vulnerabilities ?? [] };
}


export default async function RemediationDetailPage({ params }: PageProps) {
  const { id } = await params;
  const { remediation, vulnerabilities } = await getRemediation(id);
  const diffs = parseDiffsFromDescription(remediation.description);
  const platform = remediation.platforms as { name: string; repo_url: string } | null;

  return (
    <div className="space-y-8">
      {/* Back link */}
      <Link
        href="/remediation"
        className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300 transition-colors"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Remediations
      </Link>

      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <GitPullRequest className="h-5 w-5 text-zinc-400" />
            <h1 className="text-2xl font-semibold text-zinc-100">
              {remediation.title}
            </h1>
          </div>
          <div className="flex items-center gap-3">
            <FixStatus
              status={remediation.status}
              verifiedAt={remediation.merged_at || remediation.updated_at}
            />
            {platform && (
              <span className="text-sm text-zinc-500">
                on {platform.name}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          {remediation.pr_url && (
            <a
              href={remediation.pr_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-lg bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-900 hover:bg-white transition-colors"
            >
              <ExternalLink className="h-4 w-4" />
              View PR #{remediation.pr_number}
            </a>
          )}
        </div>
      </div>

      {/* Chain Walls */}
      {remediation.chain_walls_added && (
        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-4">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="h-5 w-5 text-emerald-400" />
            <h3 className="text-sm font-medium text-emerald-300">
              Chain Walls Added
            </h3>
          </div>
          <p className="text-sm text-zinc-400">
            This PR includes runtime protection rules (Chain Walls) that provide
            immediate defense while the code fix is reviewed and merged.
          </p>
        </div>
      )}

      {/* Vulnerabilities Fixed */}
      <div>
        <h2 className="text-lg font-medium text-zinc-200 mb-4 flex items-center gap-2">
          <Bug className="h-4 w-4 text-zinc-400" />
          Vulnerabilities Fixed
          <span className="ml-1 inline-flex items-center rounded-full bg-zinc-500/10 border border-zinc-500/20 px-2 py-0.5 text-xs font-medium text-zinc-400">
            {vulnerabilities.length}
          </span>
        </h2>
        {vulnerabilities.length > 0 ? (
          <div className="space-y-2">
            {vulnerabilities.map((vuln) => (
              <Link
                key={vuln.id}
                href={`/vulnerabilities/${vuln.id}`}
                className="flex items-center justify-between rounded-lg border border-[#1F1F22] bg-[#141415] p-4 hover:border-[#2A2A2E] hover:bg-[#181819] transition-all"
              >
                <div className="flex items-center gap-3">
                  <span
                    className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${severityColor(vuln.severity)}`}
                  >
                    {vuln.severity}
                  </span>
                  <span className="text-sm text-zinc-200">{vuln.title}</span>
                  {vuln.cwe_id && (
                    <span className="text-xs text-zinc-600">{vuln.cwe_id}</span>
                  )}
                </div>
                <span className="text-xs text-zinc-500">{vuln.status}</span>
              </Link>
            ))}
          </div>
        ) : (
          <div className="rounded-lg border border-[#1F1F22] bg-[#141415] p-8 text-center">
            <p className="text-sm text-zinc-500">
              No linked vulnerabilities found.
            </p>
          </div>
        )}
      </div>

      {/* Code Diffs */}
      {diffs.length > 0 && (
        <div>
          <h2 className="text-lg font-medium text-zinc-200 mb-4 flex items-center gap-2">
            <FileCode className="h-4 w-4 text-zinc-400" />
            Modified Files
            <span className="ml-1 inline-flex items-center rounded-full bg-zinc-500/10 border border-zinc-500/20 px-2 py-0.5 text-xs font-medium text-zinc-400">
              {diffs.length}
            </span>
          </h2>
          <div className="space-y-4">
            {diffs.map((diff, idx) => (
              <CodeDiffClient
                key={idx}
                filename={diff.filename}
                oldCode={diff.oldCode}
                newCode={diff.newCode}
              />
            ))}
          </div>
        </div>
      )}

      {/* Test Results */}
      <div>
        <h2 className="text-lg font-medium text-zinc-200 mb-4">
          Test Results
        </h2>
        <div className="rounded-lg border border-[#1F1F22] bg-[#141415] p-5">
          {remediation.test_results ? (
            <div className="space-y-3">
              {(
                remediation.test_results as Array<{
                  name: string;
                  passed: boolean;
                  details?: string;
                }>
              ).map((test, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-3 rounded-md bg-[#0F0F10] p-3"
                >
                  {test.passed ? (
                    <CheckCircle2 className="h-4 w-4 text-green-400 mt-0.5 shrink-0" />
                  ) : (
                    <XCircle className="h-4 w-4 text-red-400 mt-0.5 shrink-0" />
                  )}
                  <div>
                    <p className="text-sm text-zinc-200">{test.name}</p>
                    {test.details && (
                      <p className="mt-1 text-xs text-zinc-500 font-mono">
                        {test.details}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-zinc-500">
              No test results available yet.
            </p>
          )}
        </div>
      </div>

      {/* Action Buttons */}
      {(remediation.status === "pending_review" ||
        remediation.status === "approved") && (
        <ActionButtons
          remediationId={remediation.id}
          prUrl={remediation.pr_url}
          status={remediation.status}
        />
      )}
    </div>
  );
}

function ActionButtons({
  remediationId,
  prUrl,
  status,
}: {
  remediationId: string;
  prUrl: string | null;
  status: string;
}) {
  return (
    <div className="flex items-center gap-3 pt-4 border-t border-[#1F1F22]">
      <form
        action={async () => {
          "use server";
          const supabase = await createClient();

          // Update status to approved
          await supabase
            .from("remediation_prs")
            .update({ status: "approved" })
            .eq("id", remediationId);

          // If PR URL exists, attempt GitHub merge via API
          if (prUrl) {
            try {
              await fetch(`${process.env.NEXT_PUBLIC_APP_URL}/api/webhooks/github`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  action: "merge",
                  remediation_id: remediationId,
                  pr_url: prUrl,
                }),
              });
            } catch (e) {
              console.error("Failed to trigger merge:", e);
            }
          }

          redirect(`/remediation/${remediationId}`);
        }}
      >
        <button
          type="submit"
          className="inline-flex items-center gap-2 rounded-lg bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-500 transition-colors"
        >
          <CheckCircle2 className="h-4 w-4" />
          {status === "approved" ? "Merge" : "Approve & Merge"}
        </button>
      </form>

      <form
        action={async () => {
          "use server";
          const supabase = await createClient();
          await supabase
            .from("remediation_prs")
            .update({ status: "rejected" })
            .eq("id", remediationId);
          redirect(`/remediation/${remediationId}`);
        }}
      >
        <button
          type="submit"
          className="inline-flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2 text-sm font-medium text-red-400 hover:bg-red-500/20 transition-colors"
        >
          <XCircle className="h-4 w-4" />
          Reject
        </button>
      </form>
    </div>
  );
}
