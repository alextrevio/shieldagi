import { cn } from "@/lib/utils";
import { SeverityBadge } from "@/components/vulnerabilities/severity-badge";
import { ExternalLink, FileCode, Shield } from "lucide-react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type VulnStatus = "open" | "fixing" | "fixed" | "verified" | "false_positive";

export interface VulnerabilityDetail {
  id: string;
  shield_id: string;
  severity: Severity;
  cvss_score: number;
  title: string;
  description: string;
  category: string;
  file: string;
  start_line: number;
  end_line: number;
  affected_code: string;
  proof_of_concept: string | null;
  endpoint: string | null;
  status: VulnStatus;
  remediation_pr_url: string | null;
  platform_name: string;
  scan_id: string;
}

interface VulnDetailProps {
  vulnerability: VulnerabilityDetail;
}

const statusSteps: { key: VulnStatus; label: string }[] = [
  { key: "open", label: "Open" },
  { key: "fixing", label: "Fixing" },
  { key: "fixed", label: "Fixed" },
  { key: "verified", label: "Verified" },
];

const statusOrder: Record<VulnStatus, number> = {
  open: 0,
  fixing: 1,
  fixed: 2,
  verified: 3,
  false_positive: -1,
};

function getLanguageFromFile(file: string): string {
  const ext = file.split(".").pop()?.toLowerCase() ?? "";
  const map: Record<string, string> = {
    ts: "typescript",
    tsx: "tsx",
    js: "javascript",
    jsx: "jsx",
    py: "python",
    rb: "ruby",
    go: "go",
    rs: "rust",
    java: "java",
    sql: "sql",
    sh: "bash",
    yml: "yaml",
    yaml: "yaml",
    json: "json",
    html: "html",
    css: "css",
    php: "php",
    cs: "csharp",
    cpp: "cpp",
    c: "c",
  };
  return map[ext] || "text";
}

function CvssScore({ score }: { score: number }) {
  let color = "text-[#3B82F6]";
  if (score >= 9.0) color = "text-[#EF4444]";
  else if (score >= 7.0) color = "text-[#F97316]";
  else if (score >= 4.0) color = "text-[#EAB308]";

  return (
    <div className="flex items-center gap-2">
      <span className={cn("text-2xl font-bold", color)}>{score.toFixed(1)}</span>
      <span className="text-xs text-zinc-500">CVSS</span>
    </div>
  );
}

export function VulnDetail({ vulnerability }: VulnDetailProps) {
  const lang = getLanguageFromFile(vulnerability.file);
  const currentStatusIndex = statusOrder[vulnerability.status];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="rounded-lg border border-[#1F1F22] bg-[#141415] p-6">
        <div className="flex items-start justify-between">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <span className="font-mono text-xs text-zinc-500">
                {vulnerability.shield_id}
              </span>
              <SeverityBadge severity={vulnerability.severity} />
            </div>
            <h1 className="text-xl font-semibold text-zinc-100">
              {vulnerability.title}
            </h1>
            <div className="flex items-center gap-3 text-xs text-zinc-500">
              <span className="inline-flex items-center rounded-md border border-zinc-800 bg-zinc-900 px-2 py-0.5">
                {vulnerability.category}
              </span>
              <span>{vulnerability.platform_name}</span>
            </div>
          </div>
          <CvssScore score={vulnerability.cvss_score} />
        </div>

        <p className="mt-4 text-sm leading-relaxed text-zinc-400">
          {vulnerability.description}
        </p>
      </div>

      {/* Affected file */}
      <div className="rounded-lg border border-[#1F1F22] bg-[#141415] p-6">
        <div className="mb-4 flex items-center gap-2">
          <FileCode className="h-4 w-4 text-zinc-400" />
          <h3 className="text-sm font-medium text-zinc-100">Affected Code</h3>
        </div>
        <div className="mb-2 flex items-center gap-2">
          <span className="font-mono text-xs text-zinc-400">
            {vulnerability.file}
          </span>
          <span className="text-xs text-zinc-600">
            L{vulnerability.start_line}
            {vulnerability.end_line !== vulnerability.start_line &&
              `-L${vulnerability.end_line}`}
          </span>
        </div>
        <div className="overflow-hidden rounded-md border border-zinc-800">
          <SyntaxHighlighter
            language={lang}
            style={oneDark}
            showLineNumbers
            startingLineNumber={vulnerability.start_line}
            customStyle={{
              margin: 0,
              padding: "16px",
              background: "#0d0d0e",
              fontSize: "13px",
            }}
            lineNumberStyle={{
              minWidth: "3em",
              paddingRight: "1em",
              color: "#3f3f46",
            }}
          >
            {vulnerability.affected_code}
          </SyntaxHighlighter>
        </div>
      </div>

      {/* Proof of Concept */}
      {vulnerability.proof_of_concept && (
        <div className="rounded-lg border border-[#1F1F22] bg-[#141415] p-6">
          <div className="mb-4 flex items-center gap-2">
            <Shield className="h-4 w-4 text-red-400" />
            <h3 className="text-sm font-medium text-zinc-100">
              Proof of Concept
            </h3>
          </div>
          <div className="overflow-hidden rounded-md border border-zinc-800">
            <SyntaxHighlighter
              language="bash"
              style={oneDark}
              customStyle={{
                margin: 0,
                padding: "16px",
                background: "#0d0d0e",
                fontSize: "13px",
              }}
            >
              {vulnerability.proof_of_concept}
            </SyntaxHighlighter>
          </div>
        </div>
      )}

      {/* Endpoint */}
      {vulnerability.endpoint && (
        <div className="rounded-lg border border-[#1F1F22] bg-[#141415] p-4">
          <span className="text-xs text-zinc-500">Affected Endpoint</span>
          <p className="mt-1 font-mono text-sm text-zinc-300">
            {vulnerability.endpoint}
          </p>
        </div>
      )}

      {/* Remediation status */}
      <div className="rounded-lg border border-[#1F1F22] bg-[#141415] p-6">
        <h3 className="mb-4 text-sm font-medium text-zinc-100">
          Remediation Status
        </h3>

        {vulnerability.status === "false_positive" ? (
          <p className="text-sm text-zinc-500">
            Marked as false positive
          </p>
        ) : (
          <div className="flex items-center gap-2">
            {statusSteps.map((step, index) => {
              const isComplete = index <= currentStatusIndex;
              const isCurrent = index === currentStatusIndex;

              return (
                <div key={step.key} className="flex items-center gap-2">
                  {index > 0 && (
                    <div
                      className={cn(
                        "h-0.5 w-8",
                        index <= currentStatusIndex
                          ? "bg-emerald-500"
                          : "bg-zinc-800"
                      )}
                    />
                  )}
                  <div className="flex flex-col items-center gap-1">
                    <div
                      className={cn(
                        "flex h-8 w-8 items-center justify-center rounded-full border-2 text-xs font-bold",
                        isComplete
                          ? "border-emerald-500 bg-emerald-500/20 text-emerald-400"
                          : "border-zinc-700 bg-zinc-900 text-zinc-600"
                      )}
                    >
                      {index + 1}
                    </div>
                    <span
                      className={cn(
                        "text-xs",
                        isCurrent ? "font-medium text-zinc-200" : "text-zinc-600"
                      )}
                    >
                      {step.label}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {vulnerability.remediation_pr_url && (
          <a
            href={vulnerability.remediation_pr_url}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-4 inline-flex items-center gap-1.5 text-sm text-blue-400 hover:text-blue-300"
          >
            <ExternalLink className="h-3.5 w-3.5" />
            View Remediation PR
          </a>
        )}
      </div>
    </div>
  );
}
