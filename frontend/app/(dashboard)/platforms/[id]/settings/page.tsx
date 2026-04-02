"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogTrigger, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";

export default function PlatformSettingsPage({ params }: { params: { id: string } }) {
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const router = useRouter();
  const supabase = createClient();

  useEffect(() => {
    supabase.from("platforms").select("*").eq("id", params.id).single().then(({ data }) => {
      if (data) { setName(data.name); setDomain(data.domain ?? ""); }
    });
  }, [params.id, supabase]);

  async function handleSave() {
    setLoading(true);
    await supabase.from("platforms").update({ name, domain: domain || null }).eq("id", params.id);
    setLoading(false);
  }

  async function handleDelete() {
    setDeleting(true);
    await supabase.from("platforms").delete().eq("id", params.id);
    router.push("/platforms");
  }

  return (
    <div className="space-y-6 max-w-lg">
      <h1 className="text-xl font-semibold text-zinc-100">Platform Settings</h1>
      <div className="space-y-4">
        <div className="space-y-2">
          <Label>Name</Label>
          <Input value={name} onChange={e => setName(e.target.value)} />
        </div>
        <div className="space-y-2">
          <Label>Domain</Label>
          <Input value={domain} onChange={e => setDomain(e.target.value)} />
        </div>
        <Button onClick={handleSave} disabled={loading}>{loading ? "Saving..." : "Save Changes"}</Button>
      </div>

      <div className="border-t border-border pt-6">
        <h2 className="text-sm font-medium text-red-400 mb-2">Danger Zone</h2>
        <Dialog>
          <DialogTrigger><Button variant="destructive" size="sm">Delete Platform</Button></DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Delete Platform</DialogTitle>
              <DialogDescription>This will permanently delete this platform and all its scans, vulnerabilities, and remediations.</DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="destructive" onClick={handleDelete} disabled={deleting}>{deleting ? "Deleting..." : "Delete"}</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </div>
  );
}
