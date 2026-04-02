"use client";

import { useEffect, useState, useMemo } from "react";
import { createClient } from "@/lib/supabase/client";
import { LiveMonitor, type SentinelEvent } from "@/components/sentinel/live-monitor";
import { AttackMap } from "@/components/sentinel/attack-map";
import { severityColor } from "@/lib/utils";
import {
  Shield,
  AlertTriangle,
  Activity,
  Ban,
  Zap,
} from "lucide-react";

type SeverityFilter = "ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

const threatTypes = [
  "All Types",
  "SQLi",
  "XSS",
  "CSRF",
  "SSRF",
  "Brute Force",
  "DDoS",
  "Scanning",
  "Other",
];

export default function SentinelPage() {
  const [events, setEvents] = useState<SentinelEvent[]>([]);
  const [platformIds, setPlatformIds] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("ALL");
  const [typeFilter, setTypeFilter] = useState("All Types");

  // Stats
  const [activeThreats, setActiveThreats] = useState(0);
  const [eventsToday, setEventsToday] = useState(0);
  const [ipsBlocked, setIpsBlocked] = useState(0);
  const [autoPatches, setAutoPatches] = useState(0);

  useEffect(() => {
    async function fetchData() {
      const supabase = createClient();

      const {
        data: { user },
      } = await supabase.auth.getUser();

      if (!user) return;

      // Get user's platforms
      const { data: platforms } = await supabase
        .from("platforms")
        .select("id")
        .eq("user_id", user.id);

      if (!platforms || platforms.length === 0) {
        setLoading(false);
        return;
      }

      const pIds = platforms.map((p) => p.id);
      setPlatformIds(pIds);

      // Fetch recent events
      const { data: recentEvents } = await supabase
        .from("sentinel_events")
        .select("*")
        .in("platform_id", pIds)
        .order("created_at", { ascending: false })
        .limit(100);

      setEvents((recentEvents as SentinelEvent[]) ?? []);

      // Fetch stats
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      const { count: todayCount } = await supabase
        .from("sentinel_events")
        .select("*", { count: "exact", head: true })
        .in("platform_id", pIds)
        .gte("created_at", today.toISOString());

      setEventsToday(todayCount ?? 0);

      // Active threats (CRITICAL or HIGH in last hour)
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
      const { count: activeCount } = await supabase
        .from("sentinel_events")
        .select("*", { count: "exact", head: true })
        .in("platform_id", pIds)
        .in("severity", ["CRITICAL", "HIGH"])
        .gte("created_at", oneHourAgo);

      setActiveThreats(activeCount ?? 0);

      // Blocked IPs (events with action_taken = 'blocked')
      const { count: blockedCount } = await supabase
        .from("sentinel_events")
        .select("*", { count: "exact", head: true })
        .in("platform_id", pIds)
        .eq("action_taken", "blocked");

      setIpsBlocked(blockedCount ?? 0);

      // Auto-patches count
      const { count: patchCount } = await supabase
        .from("incidents")
        .select("*", { count: "exact", head: true })
        .in("platform_id", pIds)
        .eq("auto_patched", true);

      setAutoPatches(patchCount ?? 0);

      setLoading(false);
    }

    fetchData();
  }, []);

  const filteredEvents = useMemo(() => {
    let filtered = events;

    if (severityFilter !== "ALL") {
      filtered = filtered.filter((e) => e.severity === severityFilter);
    }

    if (typeFilter !== "All Types") {
      filtered = filtered.filter((e) => {
        const lower = e.threat_type.toLowerCase();
        const filterLower = typeFilter.toLowerCase();
        return lower.includes(filterLower);
      });
    }

    return filtered;
  }, [events, severityFilter, typeFilter]);

  const stats = [
    {
      label: "Active Threats",
      value: activeThreats,
      icon: AlertTriangle,
      color: activeThreats > 0 ? "text-red-400" : "text-zinc-400",
      bgColor: activeThreats > 0 ? "bg-red-500/5" : "",
    },
    {
      label: "Events Today",
      value: eventsToday,
      icon: Activity,
      color: "text-blue-400",
      bgColor: "",
    },
    {
      label: "IPs Blocked",
      value: ipsBlocked,
      icon: Ban,
      color: "text-orange-400",
      bgColor: "",
    },
    {
      label: "Auto-Patches",
      value: autoPatches,
      icon: Zap,
      color: "text-emerald-400",
      bgColor: "",
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-zinc-100 flex items-center gap-2">
          <Shield className="h-6 w-6" />
          Sentinel
        </h1>
        <p className="mt-1 text-sm text-zinc-500">
          Real-time threat monitoring and automated response.
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {stats.map((stat) => (
          <div
            key={stat.label}
            className={`rounded-lg border border-[#1F1F22] bg-[#141415] p-4 ${stat.bgColor}`}
          >
            <div className="flex items-center gap-2 mb-2">
              <stat.icon className="h-4 w-4 text-zinc-500" />
              <span className="text-xs text-zinc-500">{stat.label}</span>
            </div>
            <p className={`text-2xl font-semibold ${stat.color}`}>
              {loading ? "-" : stat.value}
            </p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1 rounded-lg bg-[#141415] border border-[#1F1F22] p-1">
          {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as SeverityFilter[]).map(
            (sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                  severityFilter === sev
                    ? "bg-[#2A2A2E] text-zinc-200"
                    : "text-zinc-500 hover:text-zinc-300"
                }`}
              >
                {sev === "ALL" ? "All" : sev}
              </button>
            )
          )}
        </div>

        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="rounded-lg border border-[#1F1F22] bg-[#141415] px-3 py-1.5 text-xs text-zinc-300 focus:outline-none focus:ring-1 focus:ring-zinc-600"
        >
          {threatTypes.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>
      </div>

      {/* Main Content */}
      <div className="grid gap-6 lg:grid-cols-[1fr_380px]">
        <LiveMonitor initialEvents={filteredEvents} platformIds={platformIds} />
        <div className="space-y-6">
          <AttackMap events={events} />
        </div>
      </div>
    </div>
  );
}
