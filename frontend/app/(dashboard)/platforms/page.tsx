import Link from "next/link";
import { createClient } from "@/lib/supabase/server";
import { Button } from "@/components/ui/button";
import { PlatformCard } from "@/components/platforms/platform-card";
import { Plus } from "lucide-react";

export default async function PlatformsPage() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  const { data: platforms } = await supabase.from("platforms").select("*").eq("user_id", user!.id).order("created_at", { ascending: false });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-zinc-100">Platforms</h1>
        <Link href="/platforms/new">
          <Button size="sm"><Plus className="h-4 w-4 mr-1" />Connect Platform</Button>
        </Link>
      </div>

      {(!platforms || platforms.length === 0) ? (
        <div className="flex flex-col items-center justify-center py-20 text-center">
          <div className="rounded-full bg-surface-raised p-4 mb-4">
            <Plus className="h-8 w-8 text-zinc-600" />
          </div>
          <h2 className="text-lg font-medium text-zinc-300 mb-2">No platforms connected</h2>
          <p className="text-sm text-zinc-600 mb-4">Connect your first platform to start scanning for vulnerabilities</p>
          <Link href="/platforms/new"><Button>Connect Platform</Button></Link>
        </div>
      ) : (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {platforms.map((p) => <PlatformCard key={p.id} platform={p} />)}
        </div>
      )}
    </div>
  );
}
