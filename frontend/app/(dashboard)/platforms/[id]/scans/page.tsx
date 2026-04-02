import Link from "next/link";
import { createClient } from "@/lib/supabase/server";
import { Badge } from "@/components/ui/badge";
import { formatDate } from "@/lib/utils";

export default async function PlatformScansPage({ params }: { params: { id: string } }) {
  const supabase = await createClient();
  const { data: scans } = await supabase.from("scans").select("*").eq("platform_id", params.id).order("created_at", { ascending: false });

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-zinc-100">Scan History</h1>
      <div className="rounded-lg border border-border bg-surface-raised overflow-hidden">
        <table className="w-full text-sm">
          <thead><tr className="border-b border-border"><th className="p-3 text-left text-xs text-zinc-500">Date</th><th className="p-3 text-left text-xs text-zinc-500">Type</th><th className="p-3 text-left text-xs text-zinc-500">Status</th><th className="p-3 text-left text-xs text-zinc-500">Risk Score</th></tr></thead>
          <tbody>
            {(scans ?? []).map(s => (
              <tr key={s.id} className="border-b border-border last:border-0 hover:bg-surface-overlay">
                <td className="p-3"><Link href={`/scans/${s.id}`} className="text-zinc-300 hover:text-blue-400">{formatDate(s.created_at)}</Link></td>
                <td className="p-3"><Badge variant="secondary">{s.type}</Badge></td>
                <td className="p-3 text-zinc-400">{s.status}</td>
                <td className="p-3 text-zinc-400">{s.risk_score?.toFixed(1) ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
