-- ShieldAGI 2.0 — Database Schema
-- Run in Supabase SQL Editor or via migrations

-- Profiles (extends Supabase Auth)
CREATE TABLE public.profiles (
    id UUID REFERENCES auth.users PRIMARY KEY,
    email TEXT NOT NULL,
    full_name TEXT,
    company TEXT,
    plan TEXT DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'enterprise')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Platforms
CREATE TABLE public.platforms (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    name TEXT NOT NULL,
    repo_url TEXT NOT NULL,
    domain TEXT,
    framework TEXT,
    status TEXT DEFAULT 'connected' CHECK (status IN ('connected', 'scanning', 'protected', 'at_risk', 'error')),
    last_scan_at TIMESTAMPTZ,
    supabase_url TEXT,
    supabase_anon_key TEXT,
    github_token_encrypted TEXT,
    ssh_config JSONB,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Scans
CREATE TABLE public.scans (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    platform_id UUID REFERENCES public.platforms(id) ON DELETE CASCADE NOT NULL,
    user_id UUID REFERENCES public.profiles(id) NOT NULL,
    type TEXT DEFAULT 'full' CHECK (type IN ('full', 'quick', 'targeted', 'rescan')),
    status TEXT DEFAULT 'queued' CHECK (status IN ('queued', 'running_recon', 'running_audit', 'running_attack', 'compiling_report', 'complete', 'failed')),
    phase TEXT DEFAULT 'recon',
    progress INTEGER DEFAULT 0,
    vulnerability_count JSONB DEFAULT '{"critical": 0, "high": 0, "medium": 0, "low": 0}',
    risk_score REAL DEFAULT 0,
    report JSONB,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Vulnerabilities
CREATE TABLE public.vulnerabilities (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    scan_id UUID REFERENCES public.scans(id) ON DELETE CASCADE NOT NULL,
    platform_id UUID REFERENCES public.platforms(id) ON DELETE CASCADE NOT NULL,
    shield_id TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('sqli', 'xss', 'csrf', 'auth', 'ssrf', 'traversal', 'idor', 'misconfig', 'dependency', 'secret')),
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    cvss_score REAL,
    title TEXT NOT NULL,
    description TEXT,
    affected_file TEXT,
    affected_lines INTEGER[],
    endpoint TEXT,
    exploitable BOOLEAN DEFAULT false,
    proof_of_concept TEXT,
    status TEXT DEFAULT 'open' CHECK (status IN ('open', 'fixing', 'fixed', 'verified', 'wont_fix', 'false_positive')),
    remediation_pr_id UUID,
    fix_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Remediations (PRs)
CREATE TABLE public.remediations (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    scan_id UUID REFERENCES public.scans(id) NOT NULL,
    platform_id UUID REFERENCES public.platforms(id) ON DELETE CASCADE NOT NULL,
    status TEXT DEFAULT 'generating' CHECK (status IN ('generating', 'pending_review', 'approved', 'merged', 'rejected', 'failed')),
    pr_url TEXT,
    pr_number INTEGER,
    branch_name TEXT,
    title TEXT,
    description TEXT,
    fixes_count INTEGER DEFAULT 0,
    chain_walls_added BOOLEAN DEFAULT false,
    files_modified TEXT[],
    test_results JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Sentinel events
CREATE TABLE public.sentinel_events (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    platform_id UUID REFERENCES public.platforms(id) ON DELETE CASCADE NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    threat_type TEXT NOT NULL,
    source_ip TEXT,
    target_endpoint TEXT,
    description TEXT,
    matched_pattern TEXT,
    action_taken TEXT,
    resolved BOOLEAN DEFAULT false,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Incidents
CREATE TABLE public.incidents (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    platform_id UUID REFERENCES public.platforms(id) ON DELETE CASCADE NOT NULL,
    sentinel_event_id UUID REFERENCES public.sentinel_events(id),
    severity TEXT NOT NULL,
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'contained', 'mitigated', 'resolved')),
    title TEXT NOT NULL,
    description TEXT,
    attack_type TEXT,
    source_ips TEXT[],
    actions_taken JSONB DEFAULT '[]',
    forensic_data JSONB,
    timeline JSONB DEFAULT '[]',
    auto_patched BOOLEAN DEFAULT false,
    patch_pr_url TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

-- Activity log
CREATE TABLE public.activity_log (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES public.profiles(id),
    platform_id UUID REFERENCES public.platforms(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Row Level Security
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.platforms ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.remediations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.activity_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users read own profile" ON public.profiles FOR ALL USING (auth.uid() = id);
CREATE POLICY "Users manage own platforms" ON public.platforms FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Users see own scans" ON public.scans FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Users see own vulns" ON public.vulnerabilities FOR ALL USING (platform_id IN (SELECT id FROM public.platforms WHERE user_id = auth.uid()));
CREATE POLICY "Users see own remediations" ON public.remediations FOR ALL USING (platform_id IN (SELECT id FROM public.platforms WHERE user_id = auth.uid()));
CREATE POLICY "Users see own sentinel events" ON public.sentinel_events FOR ALL USING (platform_id IN (SELECT id FROM public.platforms WHERE user_id = auth.uid()));
CREATE POLICY "Users see own incidents" ON public.incidents FOR ALL USING (platform_id IN (SELECT id FROM public.platforms WHERE user_id = auth.uid()));
CREATE POLICY "Users see own activity" ON public.activity_log FOR ALL USING (auth.uid() = user_id);

-- Realtime
ALTER PUBLICATION supabase_realtime ADD TABLE public.scans;
ALTER PUBLICATION supabase_realtime ADD TABLE public.sentinel_events;
ALTER PUBLICATION supabase_realtime ADD TABLE public.incidents;
ALTER PUBLICATION supabase_realtime ADD TABLE public.activity_log;

-- Auto-create profile on signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.profiles (id, email, full_name)
  VALUES (new.id, new.email, new.raw_user_meta_data->>'full_name');
  RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();
