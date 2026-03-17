"use client";
import * as React from "react";
import { cn } from "@/lib/utils";

interface TabsContextValue { activeTab: string; setActiveTab: (v: string) => void; }
const TabsContext = React.createContext<TabsContextValue>({ activeTab: "", setActiveTab: () => {} });

function Tabs({ defaultValue, children, className }: { defaultValue: string; children: React.ReactNode; className?: string }) {
  const [activeTab, setActiveTab] = React.useState(defaultValue);
  return (
    <TabsContext.Provider value={{ activeTab, setActiveTab }}>
      <div className={className}>{children}</div>
    </TabsContext.Provider>
  );
}

function TabsList({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("inline-flex h-9 items-center justify-center rounded-lg bg-surface-raised p-1 text-zinc-500", className)}>
      {children}
    </div>
  );
}

function TabsTrigger({ value, children, className }: { value: string; children: React.ReactNode; className?: string }) {
  const { activeTab, setActiveTab } = React.useContext(TabsContext);
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center whitespace-nowrap rounded-md px-3 py-1 text-sm font-medium transition-all",
        activeTab === value ? "bg-surface-overlay text-zinc-100 shadow-sm" : "text-zinc-500 hover:text-zinc-300",
        className
      )}
      onClick={() => setActiveTab(value)}
    >
      {children}
    </button>
  );
}

function TabsContent({ value, children, className }: { value: string; children: React.ReactNode; className?: string }) {
  const { activeTab } = React.useContext(TabsContext);
  if (activeTab !== value) return null;
  return <div className={cn("mt-2 animate-fade-in", className)}>{children}</div>;
}

export { Tabs, TabsList, TabsTrigger, TabsContent };
