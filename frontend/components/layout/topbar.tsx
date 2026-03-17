"use client";

import { Search, Bell } from "lucide-react";
import { Input } from "@/components/ui/input";

export function Topbar({ title, breadcrumbs }: { title: string; breadcrumbs?: { label: string; href?: string }[] }) {
  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-border bg-surface/80 backdrop-blur-sm px-6">
      <div className="flex items-center gap-2">
        {breadcrumbs && breadcrumbs.length > 0 && (
          <div className="hidden sm:flex items-center gap-1 text-sm text-zinc-500">
            {breadcrumbs.map((b, i) => (
              <span key={i}>
                {i > 0 && <span className="mx-1">/</span>}
                {b.href ? (
                  <a href={b.href} className="hover:text-zinc-300 transition-colors">{b.label}</a>
                ) : (
                  <span className="text-zinc-400">{b.label}</span>
                )}
              </span>
            ))}
          </div>
        )}
        <h1 className="text-sm font-semibold text-zinc-200 sm:hidden">{title}</h1>
      </div>

      <div className="flex items-center gap-3">
        <div className="relative hidden md:block">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-600" />
          <Input placeholder="Search..." className="w-56 pl-8 h-8 text-xs" />
        </div>
        <button className="relative p-1.5 rounded-md text-zinc-500 hover:text-zinc-300 hover:bg-surface-overlay transition-colors">
          <Bell className="h-4 w-4" />
        </button>
      </div>
    </header>
  );
}
