"use client";
import * as React from "react";
import { cn } from "@/lib/utils";

function Tooltip({ children }: { children: React.ReactNode }) {
  return <div className="relative inline-flex group">{children}</div>;
}

function TooltipTrigger({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}

function TooltipContent({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn(
      "absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 rounded bg-zinc-800 text-xs text-zinc-300 border border-border whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50",
      className
    )}>
      {children}
    </div>
  );
}

export { Tooltip, TooltipTrigger, TooltipContent };
