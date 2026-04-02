"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Shield, LayoutDashboard, Globe, Search, Bug, GitPullRequest, Eye, Settings, LogOut } from "lucide-react";
import { createClient } from "@/lib/supabase/client";
import { cn } from "@/lib/utils";
import { Separator } from "@/components/ui/separator";

const navItems = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/platforms", label: "Platforms", icon: Globe },
  { href: "/scans", label: "Scans", icon: Search },
  { href: "/vulnerabilities", label: "Vulnerabilities", icon: Bug },
  { href: "/remediation", label: "Remediation", icon: GitPullRequest },
  { href: "/sentinel", label: "Sentinel", icon: Eye },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar({ userEmail }: { userEmail?: string }) {
  const pathname = usePathname();
  const router = useRouter();
  const supabase = createClient();

  async function handleSignOut() {
    await supabase.auth.signOut();
    router.push("/login");
    router.refresh();
  }

  function isActive(href: string) {
    if (href === "/") return pathname === "/";
    return pathname.startsWith(href);
  }

  return (
    <aside className="hidden lg:flex flex-col w-60 h-screen bg-[#0F0F10] border-r border-border fixed left-0 top-0 z-40">
      <div className="flex items-center gap-2 px-5 py-5">
        <Shield className="h-6 w-6 text-blue-500" />
        <span className="text-lg font-bold text-zinc-100">ShieldAGI</span>
      </div>

      <Separator />

      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto scrollbar-thin">
        {navItems.map((item) => {
          const Icon = item.icon;
          const active = isActive(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors",
                active
                  ? "bg-blue-500/10 text-blue-400 border-l-2 border-blue-500"
                  : "text-zinc-500 hover:text-zinc-300 hover:bg-surface-overlay border-l-2 border-transparent"
              )}
            >
              <Icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      <Separator />

      <div className="p-4 space-y-3">
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-full bg-blue-600 text-xs font-medium text-white">
            {userEmail?.[0]?.toUpperCase() ?? "U"}
          </div>
          <span className="text-xs text-zinc-500 truncate flex-1">{userEmail ?? "user"}</span>
        </div>
        <button
          onClick={handleSignOut}
          className="flex w-full items-center gap-2 px-2 py-1.5 rounded-md text-xs text-zinc-500 hover:text-zinc-300 hover:bg-surface-overlay transition-colors"
        >
          <LogOut className="h-3.5 w-3.5" />
          Sign out
        </button>
      </div>
    </aside>
  );
}
