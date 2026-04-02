"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { createClient } from "@/lib/supabase/client";
import { cn, formatRelativeTime, severityColor, severityDot } from "@/lib/utils";
import {
  Shield,
  Volume2,
  VolumeX,
  Wifi,
  WifiOff,
  ArrowRight,
} from "lucide-react";

export interface SentinelEvent {
  id: string;
  severity: string;
  threat_type: string;
  source_ip: string;
  target_endpoint: string;
  description: string;
  action_taken: string;
  created_at: string;
  platform_id: string;
}

interface LiveMonitorProps {
  initialEvents?: SentinelEvent[];
  platformIds?: string[];
}

export function LiveMonitor({
  initialEvents = [],
  platformIds = [],
}: LiveMonitorProps) {
  const [events, setEvents] = useState<SentinelEvent[]>(initialEvents);
  const [isConnected, setIsConnected] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(false);
  const feedRef = useRef<HTMLDivElement>(null);
  const audioRef = useRef<HTMLAudioElement | null>(null);

  const playAlert = useCallback(() => {
    if (!soundEnabled) return;
    if (!audioRef.current) {
      audioRef.current = new Audio(
        "data:audio/wav;base64,UklGRigAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQQAAAB/"
      );
    }
    audioRef.current.play().catch(() => {});
  }, [soundEnabled]);

  useEffect(() => {
    const supabase = createClient();

    const channel = supabase
      .channel("sentinel-events-realtime")
      .on(
        "postgres_changes",
        {
          event: "INSERT",
          schema: "public",
          table: "sentinel_events",
        },
        (payload) => {
          const newEvent = payload.new as SentinelEvent;

          // Filter by platform if platformIds provided
          if (
            platformIds.length > 0 &&
            !platformIds.includes(newEvent.platform_id)
          ) {
            return;
          }

          setEvents((prev) => [newEvent, ...prev].slice(0, 100));

          if (newEvent.severity === "CRITICAL") {
            playAlert();
          }
        }
      )
      .subscribe((status) => {
        setIsConnected(status === "SUBSCRIBED");
      });

    return () => {
      supabase.removeChannel(channel);
    };
  }, [platformIds, playAlert]);

  return (
    <div className="rounded-lg border border-[#1F1F22] bg-[#141415] overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#1F1F22] bg-[#0F0F10]">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-zinc-400" />
          <h3 className="text-sm font-medium text-zinc-200">Live Monitor</h3>
          {isConnected ? (
            <span className="flex items-center gap-1 text-xs text-emerald-400">
              <Wifi className="h-3 w-3" />
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
            </span>
          ) : (
            <span className="flex items-center gap-1 text-xs text-zinc-600">
              <WifiOff className="h-3 w-3" />
            </span>
          )}
        </div>
        <button
          onClick={() => setSoundEnabled(!soundEnabled)}
          className="rounded p-1 text-zinc-500 hover:text-zinc-300 hover:bg-[#1F1F22] transition-colors"
          title={soundEnabled ? "Disable sound alerts" : "Enable sound for CRITICAL events"}
        >
          {soundEnabled ? (
            <Volume2 className="h-4 w-4" />
          ) : (
            <VolumeX className="h-4 w-4" />
          )}
        </button>
      </div>

      {/* Event Feed */}
      <div
        ref={feedRef}
        className="max-h-[600px] overflow-y-auto divide-y divide-[#1F1F22]"
      >
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 px-4">
            <Shield className="h-8 w-8 text-zinc-700 mb-3" />
            <p className="text-sm text-zinc-500">No events yet.</p>
            <p className="text-xs text-zinc-600 mt-1">
              Events will appear in real-time.
            </p>
          </div>
        ) : (
          events.map((event, idx) => (
            <div
              key={event.id}
              className={cn(
                "px-4 py-3 hover:bg-[#181819] transition-all",
                idx === 0 && "animate-in slide-in-from-top-2 duration-300"
              )}
            >
              <div className="flex items-start justify-between gap-3 mb-1.5">
                <div className="flex items-center gap-2">
                  <span
                    className={cn(
                      "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium",
                      severityColor(event.severity)
                    )}
                  >
                    {event.severity}
                  </span>
                  <span className="text-sm font-medium text-zinc-200">
                    {event.threat_type}
                  </span>
                </div>
                <span className="text-xs text-zinc-600 shrink-0">
                  {formatRelativeTime(event.created_at)}
                </span>
              </div>

              <p className="text-xs text-zinc-400 mb-2 line-clamp-2">
                {event.description}
              </p>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-xs text-zinc-500 font-mono">
                  <span>{event.source_ip}</span>
                  <ArrowRight className="h-3 w-3" />
                  <span className="text-zinc-400">
                    {event.target_endpoint}
                  </span>
                </div>
                {event.action_taken && (
                  <span className="text-xs text-zinc-500 bg-[#1F1F22] rounded px-1.5 py-0.5">
                    {event.action_taken}
                  </span>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
