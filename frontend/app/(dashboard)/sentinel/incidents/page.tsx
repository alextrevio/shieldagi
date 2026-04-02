import { createClient } from "@/lib/supabase/server";
import { redirect } from "next/navigation";
import {
  IncidentCard,
  type Incident,
} from "@/components/sentinel/incident-card";
import {
  Shield,
  AlertTriangle,
  Activity,
  Clock,
  ArrowLeft,
} from "lucide-react";
import Link from "next/link";

export const metadata = {
  title: "Incidents | ShieldAGI",
};

interface SearchParams {
  status?: string;
}

interface PageProps {
  searchParams: Promise<SearchParams>;
}

async function getIncidents(searchParams: SearchParams) {
  const supabase = await createClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) redirect("/login");

  const { data: platforms } = await supabase
    .from("platforms")
    .select("id")
    .eq("user_id", user.id);

  if (!platforms || platforms.length === 0) {
    return { incidents: [], stats: { active: 0, thisMonth: 0, avgResolution: "N/A" } };
  }

  const platformIds = platforms.map((p) => p.id);

  let query = supabase
    .from("incidents")
    .select("*")
    .in("platform_id", platformIds)
    .order("created_at", { ascending: false });

  if (searchParams.status) {
    query = query.eq("status", searchParams.status);
  }

  const { data: incidents } = await query;

  const allIncidents = (incidents ?? []) as Incident[];

  // Compute stats
  const activeCount = allIncidents.filter((i) => i.status === "active").length;

  const monthStart = new Date();
  monthStart.setDate(1);
  monthStart.setHours(0, 0, 0, 0);

  const { count: monthCount } = await supabase
    .from("incidents")
    .select("*", { count: "exact", head: true })
    .in("platform_id", platformIds)
    .gte("created_at", monthStart.toISOString());

  // Avg resolution time
  const { data: resolvedIncidents } = await supabase
    .from("incidents")
    .select("created_at, resolved_at")
    .in("platform_id", platformIds)
    .eq("status", "resolved")
    .not("resolved_at", "is", null);

  let avgResolution = "N/A";
  if (resolvedIncidents && resolvedIncidents.length > 0) {
    const totalMs = resolvedIncidents.reduce((sum, inc) => {
      const created = new Date(inc.created_at).getTime();
      const resolved = new Date(inc.resolved_at).getTime();
      return sum + (resolved - created);
    }, 0);
    const avgMs = totalMs / resolvedIncidents.length;
    const avgHours = Math.round(avgMs / (1000 * 60 * 60));
    if (avgHours < 1) {
      const avgMinutes = Math.round(avgMs / (1000 * 60));
      avgResolution = `${avgMinutes}m`;
    } else if (avgHours < 24) {
      avgResolution = `${avgHours}h`;
    } else {
      const avgDays = Math.round(avgHours / 24);
      avgResolution = `${avgDays}d`;
    }
  }

  return {
    incidents: allIncidents,
    stats: {
      active: activeCount,
      thisMonth: monthCount ?? 0,
      avgResolution,
    },
  };
}

const statusFilters = [
  { value: "", label: "All" },
  { value: "active", label: "Active" },
  { value: "contained", label: "Contained" },
  { value: "mitigated", label: "Mitigated" },
  { value: "resolved", label: "Resolved" },
];

export default async function IncidentsPage({ searchParams }: PageProps) {
  const params = await searchParams;
  const { incidents, stats } = await getIncidents(params);

  const statCards = [
    {
      label: "Active Incidents",
      value: stats.active,
      icon: AlertTriangle,
      color: stats.active > 0 ? "text-red-400" : "text-zinc-400",
    },
    {
      label: "This Month",
      value: stats.thisMonth,
      icon: Activity,
      color: "text-blue-400",
    },
    {
      label: "Avg Resolution",
      value: stats.avgResolution,
      icon: Clock,
      color: "text-emerald-400",
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <Link
          href="/sentinel"
          className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300 transition-colors mb-3"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Sentinel
        </Link>
        <h1 className="text-2xl font-semibold text-zinc-100 flex items-center gap-2">
          <Shield className="h-5 w-5" />
          Incidents
        </h1>
        <p className="mt-1 text-sm text-zinc-500">
          Security incidents across your platforms.
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        {statCards.map((stat) => (
          <div
            key={stat.label}
            className="rounded-lg border border-[#1F1F22] bg-[#141415] p-4"
          >
            <div className="flex items-center gap-2 mb-2">
              <stat.icon className="h-4 w-4 text-zinc-500" />
              <span className="text-xs text-zinc-500">{stat.label}</span>
            </div>
            <p className={`text-2xl font-semibold ${stat.color}`}>
              {stat.value}
            </p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-1 rounded-lg bg-[#141415] border border-[#1F1F22] p-1 w-fit">
        {statusFilters.map((filter) => (
          <Link
            key={filter.value}
            href={
              filter.value
                ? `/sentinel/incidents?status=${filter.value}`
                : "/sentinel/incidents"
            }
            className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              (params.status || "") === filter.value
                ? "bg-[#2A2A2E] text-zinc-200"
                : "text-zinc-500 hover:text-zinc-300"
            }`}
          >
            {filter.label}
          </Link>
        ))}
      </div>

      {/* Incidents Grid */}
      {incidents.length > 0 ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {incidents.map((incident) => (
            <IncidentCard key={incident.id} incident={incident} />
          ))}
        </div>
      ) : (
        <div className="rounded-lg border border-[#1F1F22] bg-[#141415] p-12 text-center">
          <Shield className="mx-auto h-8 w-8 text-zinc-600 mb-3" />
          <p className="text-sm text-zinc-500">No incidents found.</p>
          <p className="text-xs text-zinc-600 mt-1">
            {params.status
              ? "Try changing the filter."
              : "Incidents will appear when threats are detected."}
          </p>
        </div>
      )}
    </div>
  );
}
