import Link from "next/link";
import { notFound } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PlatformStatus } from "@/components/platforms/platform-status";
import { formatDate } from "@/lib/utils";
import { ExternalLink, Search, Bug, Settings } from "lucide-react";

export default async function PlatformDetailPage({ params }: { params: { id: string } }) {
  const supabase = await createClient();
  const { data: platform } = await supabase.from("platforms").select("*").eq("id", params.id).single();
  if (!platform) notFound();

  const { data: scans } = await supabase.from("scans").select("*").eq("platform_id", params.id).order("created_at", { ascending: false }).limit(5);
  const { data: vulns } = await supabase.from("vulnerabilities").select("id, severity, status").eq("platform_id", params.id);

  const openVulns = (vulns ?? []).filter(v => v.status === "open");
  const fixedVulns = (vulns ?? []).filter(v => v.status === "fixed" || v.status === "verified");

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold text-zinc-100">{platform.name}</h1>
            <PlatformStatus status={platform.status} />
          </div>
          <a href={platform.repo_url} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-sm text-zinc-500 hover:text-zinc-300 mt-1">
            {platform.repo_url} <ExternalLink className="h-3 w-3" />
          </a>
        </div>
        <Link href={`/scans?platform=${params.id}`}>
          <Button size="sm"><Search className="h-4 w-4 mr-1" />Run Scan</Button>
        </Link>
      </div>

      <div className="grid sm:grid-cols-4 gap-4">
        <Card><CardContent className="p-4 text-center"><p className="text-xs text-zinc-500">Total Scans</p><p className="text-2xl font-bold text-zinc-100 mt-1">{(scans ?? []).length}</p></CardContent></Card>
        <Card><CardContent className="p-4 text-center"><p className="text-xs text-zinc-500">Open Vulns</p><p className="text-2xl font-bold text-red-400 mt-1">{openVulns.length}</p></CardContent></Card>
        <Card><CardContent className="p-4 text-center"><p className="text-xs text-zinc-500">Fixed</p><p className="text-2xl font-bold text-emerald-400 mt-1">{fixedVulns.length}</p></CardContent></Card>
        <Card><CardContent className="p-4 text-center"><p className="text-xs text-zinc-500">Framework</p><p className="text-lg font-medium text-zinc-300 mt-1">{platform.framework ?? "—"}</p></CardContent></Card>
      </div>

      <div className="flex gap-2 border-b border-border pb-0">
        <Link href={`/platforms/${params.id}/scans`} className="px-3 py-2 text-sm text-zinc-500 hover:text-zinc-300 border-b-2 border-transparent hover:border-zinc-500 transition-colors flex items-center gap-1"><Search className="h-3.5 w-3.5"/>Scans</Link>
        <Link href={`/platforms/${params.id}/vulnerabilities`} className="px-3 py-2 text-sm text-zinc-500 hover:text-zinc-300 border-b-2 border-transparent hover:border-zinc-500 transition-colors flex items-center gap-1"><Bug className="h-3.5 w-3.5"/>Vulnerabilities</Link>
        <Link href={`/platforms/${params.id}/settings`} className="px-3 py-2 text-sm text-zinc-500 hover:text-zinc-300 border-b-2 border-transparent hover:border-zinc-500 transition-colors flex items-center gap-1"><Settings className="h-3.5 w-3.5"/>Settings</Link>
      </div>

      {/* Recent scans table */}
      <div className="rounded-lg border border-border bg-surface-raised overflow-hidden">
        <table className="w-full text-sm">
          <thead><tr className="border-b border-border"><th className="p-3 text-left text-xs text-zinc-500">Date</th><th className="p-3 text-left text-xs text-zinc-500">Type</th><th className="p-3 text-left text-xs text-zinc-500">Status</th><th className="p-3 text-left text-xs text-zinc-500">Vulns</th></tr></thead>
          <tbody>
            {(scans ?? []).map(s => (
              <tr key={s.id} className="border-b border-border last:border-0 hover:bg-surface-overlay">
                <td className="p-3 text-zinc-300">{formatDate(s.created_at)}</td>
                <td className="p-3"><Badge variant="secondary">{s.type}</Badge></td>
                <td className="p-3 text-zinc-400">{s.status}</td>
                <td className="p-3 text-zinc-400">{s.vulnerability_count ? Object.values(s.vulnerability_count as Record<string,number>).reduce((a:number,b:number)=>a+b,0) : 0}</td>
              </tr>
            ))}
            {(!scans || scans.length === 0) && <tr><td colSpan={4} className="p-6 text-center text-zinc-600">No scans yet</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
