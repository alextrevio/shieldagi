import Link from "next/link";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { PlatformStatus } from "./platform-status";
import { formatRelativeTime, truncate } from "@/lib/utils";

interface Platform {
  id: string;
  name: string;
  repo_url: string;
  framework?: string;
  status: string;
  last_scan_at?: string;
  vulnerability_count?: { critical: number; high: number; medium: number; low: number };
}

export function PlatformCard({ platform }: { platform: Platform }) {
  const vc = platform.vulnerability_count ?? { critical: 0, high: 0, medium: 0, low: 0 };
  return (
    <Link href={`/platforms/${platform.id}`}>
      <Card className="hover:border-border-hover transition-colors cursor-pointer">
        <CardContent className="p-5">
          <div className="flex items-start justify-between mb-3">
            <div>
              <h3 className="text-sm font-semibold text-zinc-100">{platform.name}</h3>
              <p className="text-xs text-zinc-600 mt-0.5">{truncate(platform.repo_url, 40)}</p>
            </div>
            <PlatformStatus status={platform.status} />
          </div>
          <div className="flex items-center gap-2 mb-3">
            {platform.framework && <Badge variant="secondary" className="text-[10px]">{platform.framework}</Badge>}
            {platform.last_scan_at && (
              <span className="text-xs text-zinc-600">Scanned {formatRelativeTime(platform.last_scan_at)}</span>
            )}
          </div>
          <div className="flex gap-3 text-xs">
            {vc.critical > 0 && <span className="text-severity-critical">{vc.critical} critical</span>}
            {vc.high > 0 && <span className="text-severity-high">{vc.high} high</span>}
            {vc.medium > 0 && <span className="text-severity-medium">{vc.medium} medium</span>}
            {vc.low > 0 && <span className="text-severity-low">{vc.low} low</span>}
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}
