import { cn, formatDate } from "@/lib/utils";
import { Check, X } from "lucide-react";

type FixStatusType =
  | "generating"
  | "pending_review"
  | "approved"
  | "merged"
  | "rejected"
  | "failed";

interface FixStatusProps {
  status: FixStatusType;
  verifiedAt?: string | Date | null;
}

const statusConfig: Record<
  FixStatusType,
  { label: string; dotColor: string; textColor: string; icon?: "check" | "x" | "pulse" }
> = {
  generating: {
    label: "Generating",
    dotColor: "bg-blue-400",
    textColor: "text-blue-400",
    icon: "pulse",
  },
  pending_review: {
    label: "Pending Review",
    dotColor: "bg-yellow-400",
    textColor: "text-yellow-400",
  },
  approved: {
    label: "Approved",
    dotColor: "bg-green-400",
    textColor: "text-green-400",
  },
  merged: {
    label: "Merged",
    dotColor: "bg-purple-400",
    textColor: "text-purple-400",
    icon: "check",
  },
  rejected: {
    label: "Rejected",
    dotColor: "bg-red-400",
    textColor: "text-red-400",
    icon: "x",
  },
  failed: {
    label: "Failed",
    dotColor: "bg-red-400",
    textColor: "text-red-400",
    icon: "x",
  },
};

export function FixStatus({ status, verifiedAt }: FixStatusProps) {
  const config = statusConfig[status];

  return (
    <div className="flex items-center gap-2">
      <div className="flex items-center gap-1.5">
        {config.icon === "check" ? (
          <Check className={cn("h-3.5 w-3.5", config.textColor)} />
        ) : config.icon === "x" ? (
          <X className={cn("h-3.5 w-3.5", config.textColor)} />
        ) : (
          <span
            className={cn(
              "h-2 w-2 rounded-full",
              config.dotColor,
              config.icon === "pulse" && "animate-pulse"
            )}
          />
        )}
        <span className={cn("text-sm font-medium", config.textColor)}>
          {config.label}
        </span>
      </div>
      {verifiedAt && (
        <span className="text-xs text-zinc-500">
          {formatDate(verifiedAt)}
        </span>
      )}
    </div>
  );
}
