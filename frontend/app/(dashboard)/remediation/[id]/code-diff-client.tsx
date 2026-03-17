"use client";

import { CodeDiff } from "@/components/remediation/code-diff";

interface CodeDiffClientProps {
  filename: string;
  oldCode: string;
  newCode: string;
}

export function CodeDiffClient({ filename, oldCode, newCode }: CodeDiffClientProps) {
  return <CodeDiff filename={filename} oldCode={oldCode} newCode={newCode} />;
}
