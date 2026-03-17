import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const statusConfig: Record<string, { label: string; className: string }> = {
  connected: { label: "Connected", className: "bg-zinc-700 text-zinc-300" },
  scanning: { label: "Scanning", className: "bg-blue-500/20 text-blue-400 animate-pulse" },
  protected: { label: "Protected", className: "bg-emerald-500/20 text-emerald-400" },
  at_risk: { label: "At Risk", className: "bg-yellow-500/20 text-yellow-400" },
  error: { label: "Error", className: "bg-red-500/20 text-red-400" },
};

export function PlatformStatus({ status }: { status: string }) {
  const cfg = statusConfig[status] ?? { label: status, className: "bg-zinc-700 text-zinc-300" };
  return <Badge className={cn("border-0", cfg.className)}>{cfg.label}</Badge>;
}
