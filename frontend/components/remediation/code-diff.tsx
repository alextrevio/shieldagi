"use client";

import { useState, useMemo } from "react";
import { cn } from "@/lib/utils";
import { FileCode, Columns2, AlignJustify } from "lucide-react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";

interface CodeDiffProps {
  filename: string;
  oldCode: string;
  newCode: string;
}

interface DiffLine {
  type: "added" | "removed" | "unchanged";
  content: string;
  oldLineNumber: number | null;
  newLineNumber: number | null;
}

function computeDiff(oldCode: string, newCode: string): DiffLine[] {
  const oldLines = oldCode.split("\n");
  const newLines = newCode.split("\n");
  const result: DiffLine[] = [];

  const maxLen = Math.max(oldLines.length, newLines.length);
  let oldIdx = 0;
  let newIdx = 0;

  // Simple LCS-based diff
  const lcs = computeLCS(oldLines, newLines);
  let lcsIdx = 0;

  while (oldIdx < oldLines.length || newIdx < newLines.length) {
    if (
      lcsIdx < lcs.length &&
      oldIdx < oldLines.length &&
      newIdx < newLines.length &&
      oldLines[oldIdx] === lcs[lcsIdx] &&
      newLines[newIdx] === lcs[lcsIdx]
    ) {
      result.push({
        type: "unchanged",
        content: oldLines[oldIdx],
        oldLineNumber: oldIdx + 1,
        newLineNumber: newIdx + 1,
      });
      oldIdx++;
      newIdx++;
      lcsIdx++;
    } else {
      if (
        oldIdx < oldLines.length &&
        (lcsIdx >= lcs.length || oldLines[oldIdx] !== lcs[lcsIdx])
      ) {
        result.push({
          type: "removed",
          content: oldLines[oldIdx],
          oldLineNumber: oldIdx + 1,
          newLineNumber: null,
        });
        oldIdx++;
      } else if (
        newIdx < newLines.length &&
        (lcsIdx >= lcs.length || newLines[newIdx] !== lcs[lcsIdx])
      ) {
        result.push({
          type: "added",
          content: newLines[newIdx],
          oldLineNumber: null,
          newLineNumber: newIdx + 1,
        });
        newIdx++;
      } else {
        break;
      }
    }
  }

  return result;
}

function computeLCS(a: string[], b: string[]): string[] {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    Array(n + 1).fill(0)
  );

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  const result: string[] = [];
  let i = m;
  let j = n;
  while (i > 0 && j > 0) {
    if (a[i - 1] === b[j - 1]) {
      result.unshift(a[i - 1]);
      i--;
      j--;
    } else if (dp[i - 1][j] > dp[i][j - 1]) {
      i--;
    } else {
      j--;
    }
  }

  return result;
}

function getFileExtension(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase() || "";
  const langMap: Record<string, string> = {
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
    yml: "yaml",
    yaml: "yaml",
    json: "json",
    md: "markdown",
    css: "css",
    scss: "scss",
    html: "html",
    sh: "bash",
    bash: "bash",
  };
  return langMap[ext] || "text";
}

export function CodeDiff({ filename, oldCode, newCode }: CodeDiffProps) {
  const [viewMode, setViewMode] = useState<"unified" | "split">("unified");
  const diffLines = useMemo(() => computeDiff(oldCode, newCode), [oldCode, newCode]);
  const language = getFileExtension(filename);

  return (
    <div className="rounded-lg border border-[#1F1F22] bg-[#141415] overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#1F1F22] bg-[#0F0F10]">
        <div className="flex items-center gap-2 text-sm text-zinc-300">
          <FileCode className="h-4 w-4 text-zinc-500" />
          <span className="font-mono">{filename}</span>
        </div>
        <div className="flex items-center gap-1 rounded-md bg-[#1F1F22] p-0.5">
          <button
            onClick={() => setViewMode("unified")}
            className={cn(
              "flex items-center gap-1.5 rounded px-2 py-1 text-xs transition-colors",
              viewMode === "unified"
                ? "bg-[#2A2A2E] text-zinc-200"
                : "text-zinc-500 hover:text-zinc-300"
            )}
          >
            <AlignJustify className="h-3 w-3" />
            Unified
          </button>
          <button
            onClick={() => setViewMode("split")}
            className={cn(
              "flex items-center gap-1.5 rounded px-2 py-1 text-xs transition-colors",
              viewMode === "split"
                ? "bg-[#2A2A2E] text-zinc-200"
                : "text-zinc-500 hover:text-zinc-300"
            )}
          >
            <Columns2 className="h-3 w-3" />
            Split
          </button>
        </div>
      </div>

      {viewMode === "unified" ? (
        <UnifiedView diffLines={diffLines} language={language} />
      ) : (
        <SplitView diffLines={diffLines} language={language} />
      )}
    </div>
  );
}

function UnifiedView({
  diffLines,
  language,
}: {
  diffLines: DiffLine[];
  language: string;
}) {
  return (
    <div className="overflow-x-auto text-sm font-mono">
      <table className="w-full border-collapse">
        <tbody>
          {diffLines.map((line, idx) => (
            <tr
              key={idx}
              className={cn(
                line.type === "added" && "bg-green-500/8",
                line.type === "removed" && "bg-red-500/8"
              )}
            >
              <td className="w-12 px-2 py-0 text-right text-xs text-zinc-600 select-none border-r border-[#1F1F22]">
                {line.oldLineNumber ?? ""}
              </td>
              <td className="w-12 px-2 py-0 text-right text-xs text-zinc-600 select-none border-r border-[#1F1F22]">
                {line.newLineNumber ?? ""}
              </td>
              <td className="w-5 px-1 py-0 text-center select-none">
                <span
                  className={cn(
                    "text-xs",
                    line.type === "added" && "text-green-400",
                    line.type === "removed" && "text-red-400"
                  )}
                >
                  {line.type === "added"
                    ? "+"
                    : line.type === "removed"
                    ? "-"
                    : " "}
                </span>
              </td>
              <td className="px-2 py-0">
                <SyntaxHighlighter
                  language={language}
                  style={oneDark}
                  customStyle={{
                    background: "transparent",
                    padding: 0,
                    margin: 0,
                    fontSize: "0.8125rem",
                    lineHeight: "1.5rem",
                  }}
                  codeTagProps={{
                    style: { background: "transparent" },
                  }}
                  PreTag="span"
                >
                  {line.content || " "}
                </SyntaxHighlighter>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SplitView({
  diffLines,
  language,
}: {
  diffLines: DiffLine[];
  language: string;
}) {
  const leftLines: (DiffLine | null)[] = [];
  const rightLines: (DiffLine | null)[] = [];

  let i = 0;
  while (i < diffLines.length) {
    const line = diffLines[i];
    if (line.type === "unchanged") {
      leftLines.push(line);
      rightLines.push(line);
      i++;
    } else if (line.type === "removed") {
      // Collect consecutive removed, then added
      const removedStart = i;
      while (i < diffLines.length && diffLines[i].type === "removed") i++;
      const addedStart = i;
      while (i < diffLines.length && diffLines[i].type === "added") i++;
      const removedCount = addedStart - removedStart;
      const addedCount = i - addedStart;
      const maxCount = Math.max(removedCount, addedCount);
      for (let j = 0; j < maxCount; j++) {
        leftLines.push(j < removedCount ? diffLines[removedStart + j] : null);
        rightLines.push(j < addedCount ? diffLines[addedStart + j] : null);
      }
    } else if (line.type === "added") {
      leftLines.push(null);
      rightLines.push(line);
      i++;
    }
  }

  return (
    <div className="overflow-x-auto text-sm font-mono">
      <table className="w-full border-collapse">
        <tbody>
          {leftLines.map((left, idx) => {
            const right = rightLines[idx];
            return (
              <tr key={idx}>
                <td
                  className={cn(
                    "w-10 px-2 py-0 text-right text-xs text-zinc-600 select-none border-r border-[#1F1F22]",
                    left?.type === "removed" && "bg-red-500/8"
                  )}
                >
                  {left?.oldLineNumber ?? ""}
                </td>
                <td
                  className={cn(
                    "w-1/2 px-2 py-0 border-r border-[#1F1F22]",
                    left?.type === "removed" && "bg-red-500/8"
                  )}
                >
                  {left ? (
                    <SyntaxHighlighter
                      language={language}
                      style={oneDark}
                      customStyle={{
                        background: "transparent",
                        padding: 0,
                        margin: 0,
                        fontSize: "0.8125rem",
                        lineHeight: "1.5rem",
                      }}
                      codeTagProps={{
                        style: { background: "transparent" },
                      }}
                      PreTag="span"
                    >
                      {left.content || " "}
                    </SyntaxHighlighter>
                  ) : (
                    <span>&nbsp;</span>
                  )}
                </td>
                <td
                  className={cn(
                    "w-10 px-2 py-0 text-right text-xs text-zinc-600 select-none border-r border-[#1F1F22]",
                    right?.type === "added" && "bg-green-500/8"
                  )}
                >
                  {right?.newLineNumber ?? ""}
                </td>
                <td
                  className={cn(
                    "w-1/2 px-2 py-0",
                    right?.type === "added" && "bg-green-500/8"
                  )}
                >
                  {right ? (
                    <SyntaxHighlighter
                      language={language}
                      style={oneDark}
                      customStyle={{
                        background: "transparent",
                        padding: 0,
                        margin: 0,
                        fontSize: "0.8125rem",
                        lineHeight: "1.5rem",
                      }}
                      codeTagProps={{
                        style: { background: "transparent" },
                      }}
                      PreTag="span"
                    >
                      {right.content || " "}
                    </SyntaxHighlighter>
                  ) : (
                    <span>&nbsp;</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
