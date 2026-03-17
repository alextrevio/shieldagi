"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { cn } from "@/lib/utils";

const statuses = [
  { value: "all", label: "All" },
  { value: "running", label: "Running" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed" },
  { value: "queued", label: "Queued" },
];

export function ScansFilterClient({ currentStatus }: { currentStatus: string }) {
  const router = useRouter();

  function handleFilter(status: string) {
    const params = new URLSearchParams();
    if (status !== "all") {
      params.set("status", status);
    }
    const qs = params.toString();
    router.push(`/scans${qs ? `?${qs}` : ""}`);
  }

  return (
    <div className="mb-6 flex items-center gap-1 rounded-lg border border-[#1F1F22] bg-[#141415] p-1">
      {statuses.map((s) => (
        <button
          key={s.value}
          onClick={() => handleFilter(s.value)}
          className={cn(
            "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
            currentStatus === s.value
              ? "bg-zinc-800 text-zinc-100"
              : "text-zinc-500 hover:text-zinc-300"
          )}
        >
          {s.label}
        </button>
      ))}
    </div>
  );
}
