"use client";
import * as React from "react";
import { cn } from "@/lib/utils";
import { X } from "lucide-react";

interface SheetContextValue { open: boolean; setOpen: (v: boolean) => void; }
const SheetContext = React.createContext<SheetContextValue>({ open: false, setOpen: () => {} });

function Sheet({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = React.useState(false);
  return <SheetContext.Provider value={{ open, setOpen }}>{children}</SheetContext.Provider>;
}

function SheetTrigger({ children, asChild }: { children: React.ReactNode; asChild?: boolean }) {
  const { setOpen } = React.useContext(SheetContext);
  if (asChild && React.isValidElement(children)) {
    return React.cloneElement(children as React.ReactElement<{ onClick: () => void }>, { onClick: () => setOpen(true) });
  }
  return <button onClick={() => setOpen(true)}>{children}</button>;
}

function SheetContent({ children, className, side = "left" }: { children: React.ReactNode; className?: string; side?: "left" | "right" }) {
  const { open, setOpen } = React.useContext(SheetContext);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50">
      <div className="fixed inset-0 bg-black/60" onClick={() => setOpen(false)} />
      <div className={cn(
        "fixed inset-y-0 z-50 w-72 bg-surface-raised border-r border-border p-6 shadow-xl transition-transform",
        side === "left" ? "left-0" : "right-0",
        className
      )}>
        <button className="absolute right-4 top-4 text-zinc-500 hover:text-zinc-300" onClick={() => setOpen(false)}>
          <X className="h-4 w-4" />
        </button>
        {children}
      </div>
    </div>
  );
}

function SheetHeader({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("flex flex-col space-y-2 mb-4", className)}>{children}</div>;
}

function SheetTitle({ children, className }: { children: React.ReactNode; className?: string }) {
  return <h2 className={cn("text-lg font-semibold text-zinc-100", className)}>{children}</h2>;
}

export { Sheet, SheetTrigger, SheetContent, SheetHeader, SheetTitle };
