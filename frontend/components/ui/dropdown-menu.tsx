"use client";
import * as React from "react";
import { cn } from "@/lib/utils";

interface DropdownContextValue { open: boolean; setOpen: (v: boolean) => void; }
const DropdownContext = React.createContext<DropdownContextValue>({ open: false, setOpen: () => {} });

function DropdownMenu({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = React.useState(false);
  return <DropdownContext.Provider value={{ open, setOpen }}><div className="relative inline-block">{children}</div></DropdownContext.Provider>;
}

function DropdownMenuTrigger({ children, asChild }: { children: React.ReactNode; asChild?: boolean }) {
  const { open, setOpen } = React.useContext(DropdownContext);
  if (asChild && React.isValidElement(children)) {
    return React.cloneElement(children as React.ReactElement<{ onClick: () => void }>, { onClick: () => setOpen(!open) });
  }
  return <button onClick={() => setOpen(!open)}>{children}</button>;
}

function DropdownMenuContent({ children, className, align = "end" }: { children: React.ReactNode; className?: string; align?: "start" | "end" }) {
  const { open, setOpen } = React.useContext(DropdownContext);
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    if (open) document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open, setOpen]);

  if (!open) return null;
  return (
    <div ref={ref} className={cn(
      "absolute z-50 mt-1 min-w-[8rem] overflow-hidden rounded-md border border-border bg-surface-raised p-1 shadow-xl animate-fade-in",
      align === "end" ? "right-0" : "left-0",
      className
    )}>
      {children}
    </div>
  );
}

function DropdownMenuItem({ children, className, onClick, destructive }: { children: React.ReactNode; className?: string; onClick?: () => void; destructive?: boolean }) {
  const { setOpen } = React.useContext(DropdownContext);
  return (
    <button
      className={cn(
        "relative flex w-full cursor-pointer select-none items-center rounded-sm px-2 py-1.5 text-sm outline-none transition-colors hover:bg-surface-overlay",
        destructive ? "text-red-400 hover:text-red-300" : "text-zinc-300",
        className
      )}
      onClick={() => { onClick?.(); setOpen(false); }}
    >
      {children}
    </button>
  );
}

function DropdownMenuSeparator({ className }: { className?: string }) {
  return <div className={cn("-mx-1 my-1 h-px bg-border", className)} />;
}

export { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator };
