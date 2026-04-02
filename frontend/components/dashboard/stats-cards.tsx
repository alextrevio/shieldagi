import { Globe, Bug, AlertTriangle, Activity } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

interface StatsCardsProps {
  platformCount: number;
  openVulns: number;
  threatsToday: number;
  uptimePercent: number;
}

const stats = [
  { key: "platforms", label: "Platforms Protected", icon: Globe, color: "text-blue-400" },
  { key: "vulns", label: "Open Vulnerabilities", icon: Bug, color: "text-red-400" },
  { key: "threats", label: "Threats Today", icon: AlertTriangle, color: "text-orange-400" },
  { key: "uptime", label: "Uptime", icon: Activity, color: "text-emerald-400" },
] as const;

export function StatsCards({ platformCount, openVulns, threatsToday, uptimePercent }: StatsCardsProps) {
  const values: Record<string, string> = {
    platforms: String(platformCount),
    vulns: String(openVulns),
    threats: String(threatsToday),
    uptime: `${uptimePercent}%`,
  };

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {stats.map((s) => {
        const Icon = s.icon;
        return (
          <Card key={s.key}>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-zinc-500">{s.label}</p>
                  <p className="text-2xl font-bold text-zinc-100 mt-1">{values[s.key]}</p>
                </div>
                <Icon className={`h-8 w-8 ${s.color} opacity-50`} />
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
