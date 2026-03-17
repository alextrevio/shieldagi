"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function ConnectForm() {
  const [name, setName] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [domain, setDomain] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [supabaseUrl, setSupabaseUrl] = useState("");
  const [supabaseKey, setSupabaseKey] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();
  const supabase = createClient();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    const { data: { user } } = await supabase.auth.getUser();
    if (!user) { setError("Not authenticated"); setLoading(false); return; }

    const { data: platform, error: insertErr } = await supabase.from("platforms").insert({
      user_id: user.id,
      name,
      repo_url: repoUrl,
      domain: domain || null,
      github_token_encrypted: githubToken || null,
      supabase_url: supabaseUrl || null,
      supabase_anon_key: supabaseKey || null,
    }).select().single();

    if (insertErr) { setError(insertErr.message); setLoading(false); return; }

    // Trigger initial scan
    await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ platform_id: platform.id, type: "full" }),
    });

    router.push(`/platforms/${platform.id}`);
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-6 max-w-lg">
      <div className="space-y-4">
        <h3 className="text-sm font-medium text-zinc-400">Repository</h3>
        <div className="space-y-2">
          <Label>Platform Name</Label>
          <Input placeholder="My App" value={name} onChange={e => setName(e.target.value)} required />
        </div>
        <div className="space-y-2">
          <Label>Repository URL</Label>
          <Input placeholder="https://github.com/user/repo" value={repoUrl} onChange={e => setRepoUrl(e.target.value)} required />
        </div>
        <div className="space-y-2">
          <Label>Domain (optional)</Label>
          <Input placeholder="myapp.com" value={domain} onChange={e => setDomain(e.target.value)} />
        </div>
      </div>

      <div className="space-y-4">
        <h3 className="text-sm font-medium text-zinc-400">GitHub Integration</h3>
        <div className="space-y-2">
          <Label>GitHub Personal Access Token</Label>
          <Input type="password" placeholder="ghp_..." value={githubToken} onChange={e => setGithubToken(e.target.value)} />
          <p className="text-xs text-zinc-600">Required for creating remediation PRs</p>
        </div>
      </div>

      <div className="space-y-4">
        <h3 className="text-sm font-medium text-zinc-400">Supabase (optional)</h3>
        <div className="space-y-2">
          <Label>Supabase URL</Label>
          <Input placeholder="https://xxx.supabase.co" value={supabaseUrl} onChange={e => setSupabaseUrl(e.target.value)} />
        </div>
        <div className="space-y-2">
          <Label>Supabase Anon Key</Label>
          <Input type="password" placeholder="eyJ..." value={supabaseKey} onChange={e => setSupabaseKey(e.target.value)} />
        </div>
      </div>

      {error && <p className="text-sm text-red-400">{error}</p>}

      <Button type="submit" disabled={loading} className="w-full">
        {loading ? "Connecting..." : "Connect & Scan"}
      </Button>
    </form>
  );
}
