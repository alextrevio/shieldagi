import { cn } from "@/lib/utils";
import { SeverityBadge } from "@/components/vulnerabilities/severity-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Check, X } from "lucide-react";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface ScanVulnerability {
  id: string;
  shield_id: string;
  severity: Severity;
  category: string;
  title: string;
  file: string;
  exploitable: boolean;
  status: "open" | "fixing" | "fixed" | "verified" | "false_positive";
}

interface ScanResultsProps {
  vulnerabilities: ScanVulnerability[];
}

const severityOrder: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

const statusLabels: Record<ScanVulnerability["status"], { label: string; color: string }> = {
  open: { label: "Open", color: "text-red-400" },
  fixing: { label: "Fixing", color: "text-yellow-400" },
  fixed: { label: "Fixed", color: "text-emerald-400" },
  verified: { label: "Verified", color: "text-blue-400" },
  false_positive: { label: "False Positive", color: "text-zinc-500" },
};

export function ScanResults({ vulnerabilities }: ScanResultsProps) {
  const sorted = [...vulnerabilities].sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
  );

  const counts = {
    critical: vulnerabilities.filter((v) => v.severity === "CRITICAL").length,
    high: vulnerabilities.filter((v) => v.severity === "HIGH").length,
    medium: vulnerabilities.filter((v) => v.severity === "MEDIUM").length,
    low: vulnerabilities.filter((v) => v.severity === "LOW").length,
  };

  return (
    <div className="rounded-lg border border-[#1F1F22] bg-[#141415]">
      {/* Summary row */}
      <div className="flex items-center gap-6 border-b border-[#1F1F22] px-4 py-3">
        <span className="text-sm font-medium text-zinc-100">
          {vulnerabilities.length} Vulnerabilities Found
        </span>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-bold text-[#EF4444]">
              {counts.critical}
            </span>
            <span className="text-xs text-zinc-500">Critical</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-bold text-[#F97316]">
              {counts.high}
            </span>
            <span className="text-xs text-zinc-500">High</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-bold text-[#EAB308]">
              {counts.medium}
            </span>
            <span className="text-xs text-zinc-500">Medium</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-bold text-[#3B82F6]">
              {counts.low}
            </span>
            <span className="text-xs text-zinc-500">Low</span>
          </div>
        </div>
      </div>

      {/* Table */}
      <Table>
        <TableHeader>
          <TableRow className="border-[#1F1F22] hover:bg-transparent">
            <TableHead className="text-xs font-medium text-zinc-500">
              Shield ID
            </TableHead>
            <TableHead className="text-xs font-medium text-zinc-500">
              Severity
            </TableHead>
            <TableHead className="text-xs font-medium text-zinc-500">
              Category
            </TableHead>
            <TableHead className="text-xs font-medium text-zinc-500">
              Title
            </TableHead>
            <TableHead className="text-xs font-medium text-zinc-500">
              File
            </TableHead>
            <TableHead className="text-xs font-medium text-zinc-500">
              Exploitable
            </TableHead>
            <TableHead className="text-xs font-medium text-zinc-500">
              Status
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sorted.map((vuln) => {
            const statusInfo = statusLabels[vuln.status];
            return (
              <TableRow
                key={vuln.id}
                className="border-[#1F1F22] hover:bg-zinc-900/50"
              >
                <TableCell className="font-mono text-xs text-zinc-400">
                  {vuln.shield_id}
                </TableCell>
                <TableCell>
                  <SeverityBadge severity={vuln.severity} />
                </TableCell>
                <TableCell>
                  <span className="inline-flex items-center rounded-md border border-zinc-800 bg-zinc-900 px-2 py-0.5 text-xs text-zinc-400">
                    {vuln.category}
                  </span>
                </TableCell>
                <TableCell className="max-w-[300px] truncate text-sm text-zinc-200">
                  {vuln.title}
                </TableCell>
                <TableCell className="max-w-[200px] truncate font-mono text-xs text-zinc-500">
                  {vuln.file}
                </TableCell>
                <TableCell>
                  {vuln.exploitable ? (
                    <Check className="h-4 w-4 text-red-400" />
                  ) : (
                    <X className="h-4 w-4 text-zinc-600" />
                  )}
                </TableCell>
                <TableCell>
                  <span className={cn("text-xs font-medium", statusInfo.color)}>
                    {statusInfo.label}
                  </span>
                </TableCell>
              </TableRow>
            );
          })}
          {sorted.length === 0 && (
            <TableRow>
              <TableCell
                colSpan={7}
                className="py-8 text-center text-sm text-zinc-500"
              >
                No vulnerabilities found in this scan.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  );
}
