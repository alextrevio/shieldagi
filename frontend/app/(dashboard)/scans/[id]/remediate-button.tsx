"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Wrench, Loader2 } from "lucide-react";

interface RemediateButtonProps {
  scanId: string;
  platformId: string;
}

export function RemediateButton({ scanId, platformId }: RemediateButtonProps) {
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  async function handleRemediate() {
    setLoading(true);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          platform_id: platformId,
          type: "remediation",
          source_scan_id: scanId,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        router.push(`/scans/${data.id}`);
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <button
      onClick={handleRemediate}
      disabled={loading}
      className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-emerald-500 disabled:opacity-50"
    >
      {loading ? (
        <Loader2 className="h-4 w-4 animate-spin" />
      ) : (
        <Wrench className="h-4 w-4" />
      )}
      Remediate All
    </button>
  );
}
