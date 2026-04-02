"use client";
import * as React from "react";
import { cn } from "@/lib/utils";

interface SwitchProps {
  checked?: boolean;
  onCheckedChange?: (checked: boolean) => void;
  className?: string;
  disabled?: boolean;
}

function Switch({ checked = false, onCheckedChange, className, disabled }: SwitchProps) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      className={cn(
        "peer inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        checked ? "bg-blue-600" : "bg-zinc-700",
        className
      )}
      onClick={() => onCheckedChange?.(!checked)}
    >
      <span className={cn(
        "pointer-events-none block h-4 w-4 rounded-full bg-white shadow-lg transition-transform",
        checked ? "translate-x-4" : "translate-x-0"
      )} />
    </button>
  );
}

export { Switch };
