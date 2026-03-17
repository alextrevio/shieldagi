import Link from "next/link";
import { createClient } from "@/lib/supabase/server";
import { Badge } from "@/components/ui/badge";
import { severityColor } from "@/lib/utils";
import { cn } from "@/lib/utils";

export default async function PlatformVulnsPage({ params }: { params: { id: string } }) {
  const supabase = await createClient();
  const { data: vulns } = await supabase.from("vulnerabilities").select("*").eq("platform_id", params.id).order("severity");

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-zinc-100">Vulnerabilities</h1>
      <div className="rounded-lg border border-border bg-surface-raised overflow-hidden">
        <table className="w-full text-sm">
          <thead><tr className="border-b border-border"><th className="p-3 text-left text-xs text-zinc-500">ID</th><th className="p-3 text-left text-xs text-zinc-500">Severity</th><th className="p-3 text-left text-xs text-zinc-500">Title</th><th className="p-3 text-left text-xs text-zinc-500">Category</th><th className="p-3 text-left text-xs text-zinc-500">Status</th></tr></thead>
          <tbody>
            {(vulns ?? []).map(v => (
              <tr key={v.id} className="border-b border-border last:border-0 hover:bg-surface-overlay">
                <td className="p-3"><Link href={`/vulnerabilities/${v.id}`} className="text-zinc-400 hover:text-blue-400 font-mono text-xs">{v.shield_id}</Link></td>
                <td className="p-3"><span className={cn("px-2 py-0.5 rounded text-xs font-semibold", severityColor(v.severity))}>{v.severity}</span></td>
                <td className="p-3 text-zinc-300">{v.title}</td>
                <td className="p-3"><Badge variant="secondary" className="text-[10px]">{v.category}</Badge></td>
                <td className="p-3 text-zinc-500">{v.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
