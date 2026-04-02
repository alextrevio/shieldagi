import { createClient } from "@/lib/supabase/server";
import { StatsCards } from "@/components/dashboard/stats-cards";
import { ThreatLevelGauge } from "@/components/dashboard/threat-level-gauge";
import { VulnerabilityChart } from "@/components/dashboard/vulnerability-chart";
import { RecentActivity } from "@/components/dashboard/recent-activity";
import { PlatformHealth } from "@/components/dashboard/platform-health";

function getThreatLevel(criticals: number, highs: number): "CLEAR" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
  if (criticals > 0) return "CRITICAL";
  if (highs > 3) return "HIGH";
  if (highs > 0) return "MEDIUM";
  return "CLEAR";
}

export default async function DashboardPage() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  const { data: platforms } = await supabase.from("platforms").select("*").eq("user_id", user!.id);
  const { data: openVulns } = await supabase.from("vulnerabilities").select("id, severity").in("platform_id", (platforms ?? []).map(p => p.id)).eq("status", "open");
  const { data: todayEvents } = await supabase.from("sentinel_events").select("id").in("platform_id", (platforms ?? []).map(p => p.id)).gte("created_at", new Date(Date.now() - 86400000).toISOString());
  const { data: activities } = await supabase.from("activity_log").select("*").eq("user_id", user!.id).order("created_at", { ascending: false }).limit(20);

  const vulns = openVulns ?? [];
  const criticals = vulns.filter(v => v.severity === "CRITICAL").length;
  const highs = vulns.filter(v => v.severity === "HIGH").length;

  // Generate chart data (last 30 days placeholder)
  const chartData = Array.from({ length: 30 }, (_, i) => {
    const d = new Date();
    d.setDate(d.getDate() - (29 - i));
    return { date: `${d.getMonth() + 1}/${d.getDate()}`, found: 0, fixed: 0 };
  });

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-zinc-100">Overview</h1>

      <StatsCards
        platformCount={(platforms ?? []).length}
        openVulns={vulns.length}
        threatsToday={(todayEvents ?? []).length}
        uptimePercent={99.9}
      />

      <div className="grid lg:grid-cols-2 gap-6">
        <ThreatLevelGauge level={getThreatLevel(criticals, highs)} openVulns={vulns.length} platformCount={(platforms ?? []).length} />
        <VulnerabilityChart data={chartData} />
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <RecentActivity activities={(activities ?? []).map(a => ({ ...a, platform_name: (platforms ?? []).find(p => p.id === a.platform_id)?.name }))} />
        <PlatformHealth platforms={(platforms ?? []).map(p => ({ ...p, vuln_count: vulns.filter(v => v.platform_id === p.id).length }))} />
      </div>
    </div>
  );
}
