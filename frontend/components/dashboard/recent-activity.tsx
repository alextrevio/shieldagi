import { cn, formatRelativeTime } from "@/lib/utils";
import { ScrollArea } from "@/components/ui/scroll-area";

interface Activity {
  id: string;
  action: string;
  details?: Record<string, unknown>;
  platform_name?: string;
  created_at: string;
}

const actionColors: Record<string, string> = {
  scan_started: "bg-blue-500",
  scan_completed: "bg-blue-500",
  vuln_found: "bg-red-500",
  fix_applied: "bg-emerald-500",
  threat_detected: "bg-orange-500",
  platform_connected: "bg-blue-500",
};

export function RecentActivity({ activities }: { activities: Activity[] }) {
  return (
    <div className="rounded-lg border border-border bg-surface-raised p-6">
      <p className="text-xs text-zinc-500 uppercase tracking-wider mb-4">Recent Activity</p>
      <ScrollArea className="h-72">
        <div className="space-y-3">
          {activities.length === 0 && <p className="text-sm text-zinc-600">No activity yet</p>}
          {activities.map((a) => (
            <div key={a.id} className="flex items-start gap-3">
              <span className={cn("mt-1.5 h-2 w-2 rounded-full shrink-0", actionColors[a.action] ?? "bg-zinc-600")} />
              <div className="flex-1 min-w-0">
                <p className="text-sm text-zinc-300">{a.action.replace(/_/g, " ")}</p>
                {a.platform_name && <p className="text-xs text-zinc-600">{a.platform_name}</p>}
              </div>
              <span className="text-xs text-zinc-600 shrink-0">{formatRelativeTime(a.created_at)}</span>
            </div>
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}
