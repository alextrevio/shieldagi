import { cn, formatRelativeTime, severityDot } from "@/lib/utils";
import {
  AlertTriangle,
  Bug,
  Globe,
  Zap,
  Shield,
  Search,
  Server,
  Code,
  ArrowRight,
} from "lucide-react";
import type { SentinelEvent } from "./live-monitor";

interface ThreatFeedProps {
  events: SentinelEvent[];
}

const threatIcons: Record<string, React.ElementType> = {
  SQLi: Bug,
  XSS: Code,
  CSRF: Shield,
  SSRF: Server,
  "Brute Force": Zap,
  DDoS: Globe,
  Scanning: Search,
  Other: AlertTriangle,
};

function getThreatIcon(threatType: string) {
  const Icon =
    threatIcons[threatType] ||
    Object.entries(threatIcons).find(([key]) =>
      threatType.toLowerCase().includes(key.toLowerCase())
    )?.[1] ||
    AlertTriangle;
  return Icon;
}

const severityBorderColor: Record<string, string> = {
  CRITICAL: "border-l-[#EF4444]",
  HIGH: "border-l-[#F97316]",
  MEDIUM: "border-l-[#EAB308]",
  LOW: "border-l-[#3B82F6]",
};

function groupEventsByDate(
  events: SentinelEvent[]
): Record<string, SentinelEvent[]> {
  const groups: Record<string, SentinelEvent[]> = {};

  for (const event of events) {
    const date = new Date(event.created_at);
    const key = date.toLocaleDateString("en-US", {
      weekday: "long",
      month: "long",
      day: "numeric",
      year: "numeric",
    });
    if (!groups[key]) groups[key] = [];
    groups[key].push(event);
  }

  return groups;
}

export function ThreatFeed({ events }: ThreatFeedProps) {
  const grouped = groupEventsByDate(events);

  if (events.length === 0) {
    return (
      <div className="rounded-lg border border-[#1F1F22] bg-[#141415] p-12 text-center">
        <Shield className="mx-auto h-8 w-8 text-zinc-600 mb-3" />
        <p className="text-sm text-zinc-500">No threat events recorded.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {Object.entries(grouped).map(([date, dateEvents]) => (
        <div key={date}>
          <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-3 px-1">
            {date}
          </h3>
          <div className="space-y-1">
            {dateEvents.map((event) => {
              const Icon = getThreatIcon(event.threat_type);
              const borderColor =
                severityBorderColor[event.severity] || "border-l-zinc-600";

              return (
                <div
                  key={event.id}
                  className={cn(
                    "flex items-start gap-3 rounded-lg border border-[#1F1F22] border-l-2 bg-[#141415] p-4",
                    "hover:bg-[#181819] transition-colors",
                    borderColor
                  )}
                >
                  <div className="mt-0.5">
                    <Icon className="h-4 w-4 text-zinc-500" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-medium text-zinc-200">
                        {event.threat_type}
                      </span>
                      <span
                        className={cn(
                          "h-2 w-2 rounded-full",
                          severityDot(event.severity)
                        )}
                      />
                    </div>
                    <p className="text-xs text-zinc-400 mb-2 line-clamp-2">
                      {event.description}
                    </p>
                    <div className="flex items-center gap-1.5 text-xs text-zinc-500 font-mono">
                      <span>{event.source_ip}</span>
                      <ArrowRight className="h-3 w-3" />
                      <span className="text-zinc-400">
                        {event.target_endpoint}
                      </span>
                    </div>
                  </div>
                  <span className="text-xs text-zinc-600 shrink-0">
                    {formatRelativeTime(event.created_at)}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
