import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors",
  {
    variants: {
      variant: {
        default: "border-transparent bg-blue-600 text-white",
        secondary: "border-transparent bg-zinc-800 text-zinc-300",
        destructive: "border-transparent bg-red-600 text-white",
        outline: "border-border text-zinc-400",
        critical: "border-severity-critical/30 bg-severity-critical/20 text-severity-critical",
        high: "border-severity-high/30 bg-severity-high/20 text-severity-high",
        medium: "border-severity-medium/30 bg-severity-medium/20 text-severity-medium",
        low: "border-severity-low/30 bg-severity-low/20 text-severity-low",
      },
    },
    defaultVariants: { variant: "default" },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
