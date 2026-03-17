import * as React from "react";
import { cn } from "@/lib/utils";

function Avatar({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <span className={cn("relative flex h-8 w-8 shrink-0 overflow-hidden rounded-full", className)}>
      {children}
    </span>
  );
}

function AvatarImage({ src, alt, className }: { src?: string; alt?: string; className?: string }) {
  if (!src) return null;
  return <img src={src} alt={alt} className={cn("aspect-square h-full w-full", className)} />;
}

function AvatarFallback({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={cn("flex h-full w-full items-center justify-center rounded-full bg-zinc-800 text-xs font-medium text-zinc-400", className)}>
      {children}
    </span>
  );
}

export { Avatar, AvatarImage, AvatarFallback };
