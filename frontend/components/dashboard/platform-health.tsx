import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { formatRelativeTime } from "@/lib/utils";
import Link from "next/link";

interface Platform {
  id: string;
  name: string;
  framework?: string;
  status: string;
  last_scan_at?: string;
  vuln_count?: number;
}

const statusDot: Record<string, string> = {
  protected: "bg-emerald-500",
  at_risk: "bg-yellow-500",
  error: "bg-red-500",
  scanning: "bg-blue-500 animate-pulse",
  connected: "bg-zinc-500",
};

export function PlatformHealth({ platforms }: { platforms: Platform[] }) {
  return (
    <div className="rounded-lg border border-border bg-surface-raised p-6">
      <p className="text-xs text-zinc-500 uppercase tracking-wider mb-4">Platform Health</p>
      <div className="space-y-3">
        {platforms.length === 0 && <p className="text-sm text-zinc-600">No platforms connected</p>}
        {platforms.map((p) => (
          <Link key={p.id} href={`/platforms/${p.id}`} className="flex items-center gap-3 p-2 rounded-md hover:bg-surface-overlay transition-colors">
            <span className={cn("h-2 w-2 rounded-full shrink-0", statusDot[p.status] ?? "bg-zinc-600")} />
            <span className="text-sm text-zinc-300 flex-1 truncate">{p.name}</span>
            {p.framework && <Badge variant="secondary" className="text-[10px]">{p.framework}</Badge>}
            {p.last_scan_at && <span className="text-xs text-zinc-600">{formatRelativeTime(p.last_scan_at)}</span>}
          </Link>
        ))}
      </div>
    </div>
  );
}
