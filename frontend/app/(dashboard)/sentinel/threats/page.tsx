import { createClient } from "@/lib/supabase/server";
import { redirect } from "next/navigation";
import { ThreatFeed } from "@/components/sentinel/threat-feed";
import type { SentinelEvent } from "@/components/sentinel/live-monitor";
import { Shield, ArrowLeft } from "lucide-react";
import Link from "next/link";
import { ThreatFilterSelect, ThreatFilterInput } from "./threat-filters";

export const metadata = {
  title: "Threat History | ShieldAGI",
};

interface SearchParams {
  severity?: string;
  platform?: string;
  from?: string;
  to?: string;
  page?: string;
}

interface PageProps {
  searchParams: Promise<SearchParams>;
}

const PAGE_SIZE = 50;

async function getThreats(searchParams: SearchParams) {
  const supabase = await createClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) redirect("/login");

  const { data: platforms } = await supabase
    .from("platforms")
    .select("id, name")
    .eq("user_id", user.id);

  if (!platforms || platforms.length === 0) {
    return { events: [], platforms: [], total: 0 };
  }

  const platformIds = searchParams.platform
    ? [searchParams.platform]
    : platforms.map((p) => p.id);

  const page = parseInt(searchParams.page || "1", 10);
  const offset = (page - 1) * PAGE_SIZE;

  let query = supabase
    .from("sentinel_events")
    .select("*", { count: "exact" })
    .in("platform_id", platformIds)
    .order("created_at", { ascending: false })
    .range(offset, offset + PAGE_SIZE - 1);

  if (searchParams.severity) {
    query = query.eq("severity", searchParams.severity.toUpperCase());
  }

  if (searchParams.from) {
    query = query.gte("created_at", new Date(searchParams.from).toISOString());
  }

  if (searchParams.to) {
    const toDate = new Date(searchParams.to);
    toDate.setHours(23, 59, 59, 999);
    query = query.lte("created_at", toDate.toISOString());
  }

  const { data: events, count } = await query;

  return {
    events: (events ?? []) as SentinelEvent[],
    platforms,
    total: count ?? 0,
  };
}

function buildSearchUrl(
  params: SearchParams,
  overrides: Record<string, string>
): string {
  const merged = { ...params, ...overrides };
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(merged)) {
    if (value) search.set(key, value);
  }
  const qs = search.toString();
  return `/sentinel/threats${qs ? `?${qs}` : ""}`;
}

export default async function ThreatsPage({ searchParams }: PageProps) {
  const params = await searchParams;
  const { events, platforms, total } = await getThreats(params);
  const currentPage = parseInt(params.page || "1", 10);
  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
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
            Threat History
          </h1>
          <p className="mt-1 text-sm text-zinc-500">
            {total} event{total !== 1 ? "s" : ""} recorded
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-end gap-4">
        <div className="space-y-1">
          <label className="text-xs text-zinc-500">Severity</label>
          <ThreatFilterSelect
            name="severity"
            value={params.severity || ""}
            options={[
              { value: "", label: "All" },
              { value: "CRITICAL", label: "Critical" },
              { value: "HIGH", label: "High" },
              { value: "MEDIUM", label: "Medium" },
              { value: "LOW", label: "Low" },
            ]}
            params={params}
          />
        </div>

        <div className="space-y-1">
          <label className="text-xs text-zinc-500">Platform</label>
          <ThreatFilterSelect
            name="platform"
            value={params.platform || ""}
            options={[
              { value: "", label: "All Platforms" },
              ...platforms.map((p) => ({ value: p.id, label: p.name })),
            ]}
            params={params}
          />
        </div>

        <div className="space-y-1">
          <label className="text-xs text-zinc-500">From</label>
          <ThreatFilterInput
            name="from"
            type="date"
            value={params.from || ""}
            params={params}
          />
        </div>

        <div className="space-y-1">
          <label className="text-xs text-zinc-500">To</label>
          <ThreatFilterInput
            name="to"
            type="date"
            value={params.to || ""}
            params={params}
          />
        </div>
      </div>

      {/* Feed */}
      <ThreatFeed events={events} />

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2 pt-4">
          {currentPage > 1 && (
            <Link
              href={buildSearchUrl(params, {
                page: String(currentPage - 1),
              })}
              className="rounded-lg border border-[#1F1F22] bg-[#141415] px-3 py-1.5 text-xs text-zinc-300 hover:bg-[#1F1F22] transition-colors"
            >
              Previous
            </Link>
          )}
          <span className="text-sm text-zinc-500">
            Page {currentPage} of {totalPages}
          </span>
          {currentPage < totalPages && (
            <Link
              href={buildSearchUrl(params, {
                page: String(currentPage + 1),
              })}
              className="rounded-lg border border-[#1F1F22] bg-[#141415] px-3 py-1.5 text-xs text-zinc-300 hover:bg-[#1F1F22] transition-colors"
            >
              Next
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
