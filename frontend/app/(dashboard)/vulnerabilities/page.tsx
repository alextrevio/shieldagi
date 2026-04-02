import { createClient } from "@/lib/supabase/server";
import { redirect } from "next/navigation";
import { cn } from "@/lib/utils";
import { VulnTableWrapper } from "./vuln-table-wrapper";

export const metadata = {
  title: "Vulnerabilities | ShieldAGI",
};

export default async function VulnerabilitiesPage() {
  const supabase = createClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const { data: vulns, error } = await supabase
    .from("vulnerabilities")
    .select(
      `
      id,
      shield_id,
      severity,
      title,
      category,
      file,
      status,
      created_at,
      scans!inner (
        platforms!inner (
          user_id
        )
      )
    `
    )
    .eq("scans.platforms.user_id", user.id)
    .order("created_at", { ascending: false });

  const vulnerabilities = (vulns ?? []).map((v: any) => ({
    id: v.id,
    shield_id: v.shield_id,
    severity: v.severity,
    title: v.title,
    category: v.category,
    file: v.file,
    status: v.status,
    created_at: v.created_at,
  }));

  const counts = {
    critical: vulnerabilities.filter((v) => v.severity === "CRITICAL").length,
    high: vulnerabilities.filter((v) => v.severity === "HIGH").length,
    medium: vulnerabilities.filter((v) => v.severity === "MEDIUM").length,
    low: vulnerabilities.filter((v) => v.severity === "LOW").length,
  };

  const summaryCards = [
    {
      label: "Critical",
      count: counts.critical,
      color: "text-[#EF4444]",
      bg: "bg-red-500/10",
      border: "border-red-500/20",
    },
    {
      label: "High",
      count: counts.high,
      color: "text-[#F97316]",
      bg: "bg-orange-500/10",
      border: "border-orange-500/20",
    },
    {
      label: "Medium",
      count: counts.medium,
      color: "text-[#EAB308]",
      bg: "bg-yellow-500/10",
      border: "border-yellow-500/20",
    },
    {
      label: "Low",
      count: counts.low,
      color: "text-[#3B82F6]",
      bg: "bg-blue-500/10",
      border: "border-blue-500/20",
    },
  ];

  return (
    <div className="min-h-screen bg-[#0A0A0B]">
      <div className="mx-auto max-w-6xl px-6 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-2xl font-semibold text-zinc-100">
            Vulnerabilities
          </h1>
          <p className="mt-1 text-sm text-zinc-500">
            All security vulnerabilities detected across your platforms.
          </p>
        </div>

        {/* Summary cards */}
        <div className="mb-6 grid grid-cols-4 gap-3">
          {summaryCards.map((card) => (
            <div
              key={card.label}
              className={cn(
                "rounded-lg border p-4",
                card.bg,
                card.border
              )}
            >
              <span className="text-xs text-zinc-500">{card.label}</span>
              <p className={cn("mt-1 text-2xl font-bold", card.color)}>
                {card.count}
              </p>
            </div>
          ))}
        </div>

        {/* Table */}
        <VulnTableWrapper vulnerabilities={vulnerabilities} />
      </div>
    </div>
  );
}
