"use client";

import { useState, useMemo } from "react";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ArrowUpDown, ExternalLink } from "lucide-react";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface Vulnerability {
  id: string;
  shield_id: string;
  severity: Severity;
  title: string;
  category: string;
  file: string;
  status: "open" | "fixing" | "fixed" | "verified" | "false_positive";
  created_at: string;
}

interface VulnTableProps {
  vulnerabilities: Vulnerability[];
  onRowClick?: (vuln: Vulnerability) => void;
}

type SortField = "severity" | "title" | "category" | "status" | "created_at";
type SortDirection = "asc" | "desc";

const severityOrder: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

const statusLabels: Record<Vulnerability["status"], { label: string; color: string }> = {
  open: { label: "Open", color: "text-red-400" },
  fixing: { label: "Fixing", color: "text-yellow-400" },
  fixed: { label: "Fixed", color: "text-emerald-400" },
  verified: { label: "Verified", color: "text-blue-400" },
  false_positive: { label: "False Positive", color: "text-zinc-500" },
};

export function VulnTable({ vulnerabilities, onRowClick }: VulnTableProps) {
  const [sortField, setSortField] = useState<SortField>("severity");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [filterCategory, setFilterCategory] = useState<string>("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");

  const categories = useMemo(
    () => Array.from(new Set(vulnerabilities.map((v) => v.category))).sort(),
    [vulnerabilities]
  );

  const filtered = useMemo(() => {
    let result = [...vulnerabilities];

    if (filterSeverity !== "all") {
      result = result.filter((v) => v.severity === filterSeverity);
    }
    if (filterCategory !== "all") {
      result = result.filter((v) => v.category === filterCategory);
    }
    if (filterStatus !== "all") {
      result = result.filter((v) => v.status === filterStatus);
    }

    result.sort((a, b) => {
      let comparison = 0;

      switch (sortField) {
        case "severity":
          comparison = severityOrder[a.severity] - severityOrder[b.severity];
          break;
        case "title":
          comparison = a.title.localeCompare(b.title);
          break;
        case "category":
          comparison = a.category.localeCompare(b.category);
          break;
        case "status":
          comparison = a.status.localeCompare(b.status);
          break;
        case "created_at":
          comparison =
            new Date(a.created_at).getTime() -
            new Date(b.created_at).getTime();
          break;
      }

      return sortDirection === "asc" ? comparison : -comparison;
    });

    return result;
  }, [vulnerabilities, sortField, sortDirection, filterSeverity, filterCategory, filterStatus]);

  function handleSort(field: SortField) {
    if (sortField === field) {
      setSortDirection((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDirection("asc");
    }
  }

  function SortableHeader({
    field,
    children,
  }: {
    field: SortField;
    children: React.ReactNode;
  }) {
    return (
      <TableHead
        className="cursor-pointer select-none text-xs font-medium text-zinc-500 hover:text-zinc-300"
        onClick={() => handleSort(field)}
      >
        <div className="flex items-center gap-1">
          {children}
          <ArrowUpDown
            className={cn(
              "h-3 w-3",
              sortField === field ? "text-zinc-300" : "text-zinc-700"
            )}
          />
        </div>
      </TableHead>
    );
  }

  return (
    <div className="space-y-3">
      {/* Filters */}
      <div className="flex items-center gap-3">
        <Select value={filterSeverity} onValueChange={setFilterSeverity}>
          <SelectTrigger className="h-8 w-[140px] border-[#1F1F22] bg-[#141415] text-xs text-zinc-300">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent className="border-[#1F1F22] bg-[#141415]">
            <SelectItem value="all" className="text-xs text-zinc-300">
              All Severities
            </SelectItem>
            <SelectItem value="CRITICAL" className="text-xs text-[#EF4444]">
              Critical
            </SelectItem>
            <SelectItem value="HIGH" className="text-xs text-[#F97316]">
              High
            </SelectItem>
            <SelectItem value="MEDIUM" className="text-xs text-[#EAB308]">
              Medium
            </SelectItem>
            <SelectItem value="LOW" className="text-xs text-[#3B82F6]">
              Low
            </SelectItem>
          </SelectContent>
        </Select>

        <Select value={filterCategory} onValueChange={setFilterCategory}>
          <SelectTrigger className="h-8 w-[160px] border-[#1F1F22] bg-[#141415] text-xs text-zinc-300">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent className="border-[#1F1F22] bg-[#141415]">
            <SelectItem value="all" className="text-xs text-zinc-300">
              All Categories
            </SelectItem>
            {categories.map((cat) => (
              <SelectItem key={cat} value={cat} className="text-xs text-zinc-300">
                {cat}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={filterStatus} onValueChange={setFilterStatus}>
          <SelectTrigger className="h-8 w-[140px] border-[#1F1F22] bg-[#141415] text-xs text-zinc-300">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent className="border-[#1F1F22] bg-[#141415]">
            <SelectItem value="all" className="text-xs text-zinc-300">
              All Statuses
            </SelectItem>
            <SelectItem value="open" className="text-xs text-red-400">
              Open
            </SelectItem>
            <SelectItem value="fixing" className="text-xs text-yellow-400">
              Fixing
            </SelectItem>
            <SelectItem value="fixed" className="text-xs text-emerald-400">
              Fixed
            </SelectItem>
            <SelectItem value="verified" className="text-xs text-blue-400">
              Verified
            </SelectItem>
            <SelectItem value="false_positive" className="text-xs text-zinc-500">
              False Positive
            </SelectItem>
          </SelectContent>
        </Select>

        <span className="ml-auto text-xs text-zinc-500">
          {filtered.length} of {vulnerabilities.length} results
        </span>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-[#1F1F22] bg-[#141415]">
        <Table>
          <TableHeader>
            <TableRow className="border-[#1F1F22] hover:bg-transparent">
              <TableHead className="text-xs font-medium text-zinc-500">
                Shield ID
              </TableHead>
              <SortableHeader field="severity">Severity</SortableHeader>
              <SortableHeader field="title">Title</SortableHeader>
              <SortableHeader field="category">Category</SortableHeader>
              <TableHead className="text-xs font-medium text-zinc-500">
                File
              </TableHead>
              <SortableHeader field="status">Status</SortableHeader>
              <TableHead className="text-xs font-medium text-zinc-500">
                Actions
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((vuln) => {
              const statusInfo = statusLabels[vuln.status];
              return (
                <TableRow
                  key={vuln.id}
                  className={cn(
                    "border-[#1F1F22] transition-colors",
                    onRowClick &&
                      "cursor-pointer hover:bg-zinc-900/50"
                  )}
                  onClick={() => onRowClick?.(vuln)}
                >
                  <TableCell className="font-mono text-xs text-zinc-400">
                    {vuln.shield_id}
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={vuln.severity} />
                  </TableCell>
                  <TableCell className="max-w-[300px] truncate text-sm text-zinc-200">
                    {vuln.title}
                  </TableCell>
                  <TableCell>
                    <span className="inline-flex items-center rounded-md border border-zinc-800 bg-zinc-900 px-2 py-0.5 text-xs text-zinc-400">
                      {vuln.category}
                    </span>
                  </TableCell>
                  <TableCell className="max-w-[200px] truncate font-mono text-xs text-zinc-500">
                    {vuln.file}
                  </TableCell>
                  <TableCell>
                    <span
                      className={cn("text-xs font-medium", statusInfo.color)}
                    >
                      {statusInfo.label}
                    </span>
                  </TableCell>
                  <TableCell>
                    <button
                      className="rounded p-1 text-zinc-500 hover:bg-zinc-800 hover:text-zinc-300"
                      onClick={(e) => {
                        e.stopPropagation();
                        onRowClick?.(vuln);
                      }}
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                    </button>
                  </TableCell>
                </TableRow>
              );
            })}
            {filtered.length === 0 && (
              <TableRow>
                <TableCell
                  colSpan={7}
                  className="py-8 text-center text-sm text-zinc-500"
                >
                  No vulnerabilities match the current filters.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
