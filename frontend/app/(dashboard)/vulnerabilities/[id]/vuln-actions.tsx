"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { cn } from "@/lib/utils";
import { Check, Flag, Loader2 } from "lucide-react";

interface VulnActionsProps {
  vulnId: string;
  currentStatus: string;
}

export function VulnActions({ vulnId, currentStatus }: VulnActionsProps) {
  const [loading, setLoading] = useState<string | null>(null);
  const router = useRouter();

  async function updateStatus(newStatus: string) {
    setLoading(newStatus);
    try {
      const res = await fetch(`/api/vulnerabilities/${vulnId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });

      if (res.ok) {
        router.refresh();
      }
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className="rounded-lg border border-[#1F1F22] bg-[#141415] p-6">
      <h3 className="mb-4 text-sm font-medium text-zinc-100">Actions</h3>
      <div className="space-y-2">
        {currentStatus !== "fixed" && currentStatus !== "verified" && (
          <button
            onClick={() => updateStatus("fixed")}
            disabled={loading !== null}
            className={cn(
              "flex w-full items-center gap-2 rounded-lg border border-[#1F1F22] px-3 py-2 text-sm transition-colors",
              "text-zinc-300 hover:bg-zinc-800 hover:text-white",
              "disabled:opacity-50"
            )}
          >
            {loading === "fixed" ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Check className="h-4 w-4 text-emerald-400" />
            )}
            Mark as Fixed
          </button>
        )}

        {currentStatus !== "false_positive" && (
          <button
            onClick={() => updateStatus("false_positive")}
            disabled={loading !== null}
            className={cn(
              "flex w-full items-center gap-2 rounded-lg border border-[#1F1F22] px-3 py-2 text-sm transition-colors",
              "text-zinc-300 hover:bg-zinc-800 hover:text-white",
              "disabled:opacity-50"
            )}
          >
            {loading === "false_positive" ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Flag className="h-4 w-4 text-zinc-500" />
            )}
            Mark as False Positive
          </button>
        )}

        {currentStatus === "fixed" && (
          <button
            onClick={() => updateStatus("verified")}
            disabled={loading !== null}
            className={cn(
              "flex w-full items-center gap-2 rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white transition-colors",
              "hover:bg-emerald-500 disabled:opacity-50"
            )}
          >
            {loading === "verified" ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Check className="h-4 w-4" />
            )}
            Verify Fix
          </button>
        )}

        {(currentStatus === "fixed" ||
          currentStatus === "verified" ||
          currentStatus === "false_positive") && (
          <button
            onClick={() => updateStatus("open")}
            disabled={loading !== null}
            className={cn(
              "flex w-full items-center gap-2 rounded-lg border border-[#1F1F22] px-3 py-2 text-sm transition-colors",
              "text-zinc-500 hover:bg-zinc-800 hover:text-zinc-300",
              "disabled:opacity-50"
            )}
          >
            {loading === "open" ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : null}
            Reopen
          </button>
        )}
      </div>
    </div>
  );
}
