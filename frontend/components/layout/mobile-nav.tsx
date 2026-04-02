"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Menu, Shield, LayoutDashboard, Globe, Search, Bug, GitPullRequest, Eye, Settings } from "lucide-react";
import { Sheet, SheetTrigger, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { cn } from "@/lib/utils";

const navItems = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/platforms", label: "Platforms", icon: Globe },
  { href: "/scans", label: "Scans", icon: Search },
  { href: "/vulnerabilities", label: "Vulnerabilities", icon: Bug },
  { href: "/remediation", label: "Remediation", icon: GitPullRequest },
  { href: "/sentinel", label: "Sentinel", icon: Eye },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function MobileNav() {
  const pathname = usePathname();

  return (
    <div className="lg:hidden">
      <Sheet>
        <SheetTrigger>
          <button className="p-2 text-zinc-400 hover:text-zinc-200">
            <Menu className="h-5 w-5" />
          </button>
        </SheetTrigger>
        <SheetContent side="left">
          <SheetHeader>
            <SheetTitle>
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-blue-500" />
                <span>ShieldAGI</span>
              </div>
            </SheetTitle>
          </SheetHeader>
          <nav className="mt-4 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    "flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors",
                    active ? "bg-blue-500/10 text-blue-400" : "text-zinc-500 hover:text-zinc-300 hover:bg-surface-overlay"
                  )}
                >
                  <Icon className="h-4 w-4" />
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </SheetContent>
      </Sheet>
    </div>
  );
}
