"use client";

import { useMemo } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import type { SentinelEvent } from "./live-monitor";

interface AttackMapProps {
  events: SentinelEvent[];
}

const attackCategories = [
  "SQLi",
  "XSS",
  "CSRF",
  "SSRF",
  "Brute Force",
  "DDoS",
  "Scanning",
  "Other",
];

const categoryColors: Record<string, string> = {
  SQLi: "#EF4444",
  XSS: "#F97316",
  CSRF: "#EAB308",
  SSRF: "#3B82F6",
  "Brute Force": "#8B5CF6",
  DDoS: "#EC4899",
  Scanning: "#6366F1",
  Other: "#71717A",
};

function categorizeEvent(threatType: string): string {
  const lower = threatType.toLowerCase();
  if (lower.includes("sql") || lower.includes("injection")) return "SQLi";
  if (lower.includes("xss") || lower.includes("cross-site scripting"))
    return "XSS";
  if (lower.includes("csrf") || lower.includes("cross-site request"))
    return "CSRF";
  if (lower.includes("ssrf") || lower.includes("server-side request"))
    return "SSRF";
  if (lower.includes("brute") || lower.includes("credential"))
    return "Brute Force";
  if (lower.includes("ddos") || lower.includes("dos") || lower.includes("flood"))
    return "DDoS";
  if (lower.includes("scan") || lower.includes("recon") || lower.includes("enum"))
    return "Scanning";
  return "Other";
}

interface TooltipProps {
  active?: boolean;
  payload?: Array<{
    value: number;
    payload: { name: string; count: number; fill: string };
  }>;
}

function CustomTooltip({ active, payload }: TooltipProps) {
  if (!active || !payload || !payload.length) return null;

  const data = payload[0].payload;
  return (
    <div className="rounded-lg border border-[#1F1F22] bg-[#0F0F10] px-3 py-2 shadow-xl">
      <p className="text-xs font-medium text-zinc-200">{data.name}</p>
      <p className="text-xs text-zinc-400">
        {data.count} event{data.count !== 1 ? "s" : ""}
      </p>
    </div>
  );
}

export function AttackMap({ events }: AttackMapProps) {
  const data = useMemo(() => {
    const counts: Record<string, number> = {};
    attackCategories.forEach((cat) => (counts[cat] = 0));

    events.forEach((event) => {
      const category = categorizeEvent(event.threat_type);
      counts[category] = (counts[category] || 0) + 1;
    });

    return attackCategories
      .map((name) => ({
        name,
        count: counts[name],
        fill: categoryColors[name],
      }))
      .sort((a, b) => b.count - a.count);
  }, [events]);

  const hasData = data.some((d) => d.count > 0);

  return (
    <div className="rounded-lg border border-[#1F1F22] bg-[#141415] p-4">
      <h3 className="text-sm font-medium text-zinc-200 mb-4">
        Attacks by Type
      </h3>
      {hasData ? (
        <ResponsiveContainer width="100%" height={280}>
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 0, right: 12, bottom: 0, left: 0 }}
          >
            <XAxis
              type="number"
              tick={{ fill: "#71717A", fontSize: 11 }}
              axisLine={{ stroke: "#1F1F22" }}
              tickLine={false}
              allowDecimals={false}
            />
            <YAxis
              type="category"
              dataKey="name"
              tick={{ fill: "#A1A1AA", fontSize: 12 }}
              axisLine={false}
              tickLine={false}
              width={80}
            />
            <Tooltip
              content={<CustomTooltip />}
              cursor={{ fill: "rgba(255,255,255,0.03)" }}
            />
            <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={20}>
              {data.map((entry, index) => (
                <Cell key={index} fill={entry.fill} fillOpacity={0.8} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <div className="flex items-center justify-center h-[280px]">
          <p className="text-sm text-zinc-600">No attack data to display.</p>
        </div>
      )}
    </div>
  );
}
