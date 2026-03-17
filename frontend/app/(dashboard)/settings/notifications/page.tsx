"use client";

import { useState, useEffect, useCallback } from "react";
import { createBrowserClient } from "@supabase/ssr";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";

interface NotificationChannels {
  telegram_enabled: boolean;
  telegram_bot_token: string;
  telegram_chat_id: string;
  slack_enabled: boolean;
  slack_webhook_url: string;
  email_enabled: boolean;
  email_address: string;
}

interface NotificationTriggers {
  critical_vulnerability: boolean;
  scan_completed: boolean;
  remediation_pr_created: boolean;
  sentinel_critical: boolean;
  sentinel_high: boolean;
  dependency_vulnerability: boolean;
}

interface NotificationSettings extends NotificationChannels, NotificationTriggers {
  id?: string;
  user_id?: string;
}

const DEFAULT_CHANNELS: NotificationChannels = {
  telegram_enabled: false,
  telegram_bot_token: "",
  telegram_chat_id: "",
  slack_enabled: false,
  slack_webhook_url: "",
  email_enabled: false,
  email_address: "",
};

const DEFAULT_TRIGGERS: NotificationTriggers = {
  critical_vulnerability: true,
  scan_completed: false,
  remediation_pr_created: true,
  sentinel_critical: true,
  sentinel_high: false,
  dependency_vulnerability: true,
};

function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  );
}

export default function NotificationsPage() {
  const [channels, setChannels] = useState<NotificationChannels>(DEFAULT_CHANNELS);
  const [triggers, setTriggers] = useState<NotificationTriggers>(DEFAULT_TRIGGERS);
  const [settingsId, setSettingsId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  const supabase = createClient();

  const loadSettings = useCallback(async () => {
    const {
      data: { user },
    } = await supabase.auth.getUser();
    if (!user) return;

    const { data, error } = await supabase
      .from("notification_settings")
      .select("*")
      .eq("user_id", user.id)
      .single();

    if (!error && data) {
      setSettingsId(data.id);
      setChannels({
        telegram_enabled: data.telegram_enabled ?? false,
        telegram_bot_token: data.telegram_bot_token ?? "",
        telegram_chat_id: data.telegram_chat_id ?? "",
        slack_enabled: data.slack_enabled ?? false,
        slack_webhook_url: data.slack_webhook_url ?? "",
        email_enabled: data.email_enabled ?? false,
        email_address: data.email_address ?? "",
      });
      setTriggers({
        critical_vulnerability: data.critical_vulnerability ?? true,
        scan_completed: data.scan_completed ?? false,
        remediation_pr_created: data.remediation_pr_created ?? true,
        sentinel_critical: data.sentinel_critical ?? true,
        sentinel_high: data.sentinel_high ?? false,
        dependency_vulnerability: data.dependency_vulnerability ?? true,
      });
    }
    setLoading(false);
  }, [supabase]);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  const handleSave = async () => {
    setSaving(true);
    setMessage(null);

    const {
      data: { user },
    } = await supabase.auth.getUser();
    if (!user) {
      setMessage({ type: "error", text: "Not authenticated." });
      setSaving(false);
      return;
    }

    const payload: NotificationSettings = {
      ...channels,
      ...triggers,
      user_id: user.id,
    };

    if (settingsId) {
      const { error } = await supabase
        .from("notification_settings")
        .update({ ...payload, updated_at: new Date().toISOString() })
        .eq("id", settingsId);

      if (error) {
        setMessage({ type: "error", text: "Failed to save notification settings." });
        setSaving(false);
        return;
      }
    } else {
      const { data, error } = await supabase
        .from("notification_settings")
        .insert(payload)
        .select("id")
        .single();

      if (error) {
        setMessage({ type: "error", text: "Failed to save notification settings." });
        setSaving(false);
        return;
      }
      setSettingsId(data.id);
    }

    setMessage({ type: "success", text: "Notification settings saved." });
    setSaving(false);
  };

  const handleTestTelegram = async () => {
    if (!channels.telegram_bot_token || !channels.telegram_chat_id) {
      setMessage({ type: "error", text: "Please enter both Telegram bot token and chat ID." });
      return;
    }

    setTesting("telegram");
    try {
      const res = await fetch(
        `https://api.telegram.org/bot${channels.telegram_bot_token}/sendMessage`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: channels.telegram_chat_id,
            text: "ShieldAGI test notification - your Telegram integration is working.",
            parse_mode: "Markdown",
          }),
        }
      );

      if (res.ok) {
        setMessage({ type: "success", text: "Telegram test message sent successfully." });
      } else {
        const data = await res.json();
        setMessage({
          type: "error",
          text: `Telegram test failed: ${data.description || "Unknown error"}`,
        });
      }
    } catch {
      setMessage({ type: "error", text: "Failed to send Telegram test message." });
    }
    setTesting(null);
  };

  const handleTestSlack = async () => {
    if (!channels.slack_webhook_url) {
      setMessage({ type: "error", text: "Please enter a Slack webhook URL." });
      return;
    }

    setTesting("slack");
    try {
      const res = await fetch(channels.slack_webhook_url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: "ShieldAGI test notification - your Slack integration is working.",
        }),
      });

      if (res.ok) {
        setMessage({ type: "success", text: "Slack test message sent successfully." });
      } else {
        setMessage({ type: "error", text: "Slack test failed. Check your webhook URL." });
      }
    } catch {
      setMessage({ type: "error", text: "Failed to send Slack test message." });
    }
    setTesting(null);
  };

  const triggerDefinitions: {
    key: keyof NotificationTriggers;
    label: string;
    description: string;
  }[] = [
    {
      key: "critical_vulnerability",
      label: "Critical vulnerability found",
      description: "Notify when a critical severity vulnerability is discovered.",
    },
    {
      key: "scan_completed",
      label: "Scan completed",
      description: "Notify when a security scan finishes.",
    },
    {
      key: "remediation_pr_created",
      label: "Remediation PR created",
      description: "Notify when a fix pull request is automatically generated.",
    },
    {
      key: "sentinel_critical",
      label: "Sentinel threat detected (CRITICAL)",
      description: "Notify on critical-severity Sentinel detections.",
    },
    {
      key: "sentinel_high",
      label: "Sentinel threat detected (HIGH)",
      description: "Notify on high-severity Sentinel detections.",
    },
    {
      key: "dependency_vulnerability",
      label: "Dependency vulnerability found",
      description: "Notify when a vulnerable dependency is identified.",
    },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="animate-pulse text-zinc-500">Loading notification settings...</div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-8 p-6">
      <div>
        <h1 className="text-2xl font-semibold text-zinc-100">Notifications</h1>
        <p className="text-sm text-zinc-500 mt-1">
          Configure how and when you receive security alerts.
        </p>
      </div>

      {message && (
        <div
          className={`px-4 py-3 rounded-md text-sm ${
            message.type === "success"
              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
              : "bg-red-500/10 text-red-400 border border-red-500/20"
          }`}
        >
          {message.text}
        </div>
      )}

      {/* Notification Channels */}
      <div className="space-y-4">
        <h2 className="text-lg font-medium text-zinc-200">Channels</h2>

        {/* Telegram */}
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-sm font-medium text-zinc-100">
                  Telegram
                </CardTitle>
                <CardDescription className="text-xs text-zinc-500 mt-1">
                  Receive alerts via Telegram bot.
                </CardDescription>
              </div>
              <Switch
                checked={channels.telegram_enabled}
                onCheckedChange={(checked) =>
                  setChannels((prev) => ({ ...prev, telegram_enabled: checked }))
                }
              />
            </div>
          </CardHeader>
          {channels.telegram_enabled && (
            <CardContent className="space-y-3">
              <div className="space-y-2">
                <Label htmlFor="telegram_bot_token" className="text-zinc-400 text-xs">
                  Bot Token
                </Label>
                <Input
                  id="telegram_bot_token"
                  type="password"
                  value={channels.telegram_bot_token}
                  onChange={(e) =>
                    setChannels((prev) => ({
                      ...prev,
                      telegram_bot_token: e.target.value,
                    }))
                  }
                  placeholder="123456789:ABCdefGhIJKlmNoPQRsTUVwxYZ"
                  className="bg-zinc-950 border-zinc-800 text-zinc-100 focus:border-indigo-500 font-mono text-sm"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="telegram_chat_id" className="text-zinc-400 text-xs">
                  Chat ID
                </Label>
                <Input
                  id="telegram_chat_id"
                  value={channels.telegram_chat_id}
                  onChange={(e) =>
                    setChannels((prev) => ({
                      ...prev,
                      telegram_chat_id: e.target.value,
                    }))
                  }
                  placeholder="-1001234567890"
                  className="bg-zinc-950 border-zinc-800 text-zinc-100 focus:border-indigo-500 font-mono text-sm"
                />
              </div>
              <Button
                size="sm"
                variant="outline"
                onClick={handleTestTelegram}
                disabled={testing === "telegram"}
                className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
              >
                {testing === "telegram" ? "Sending..." : "Send Test Message"}
              </Button>
            </CardContent>
          )}
        </Card>

        {/* Slack */}
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-sm font-medium text-zinc-100">
                  Slack
                </CardTitle>
                <CardDescription className="text-xs text-zinc-500 mt-1">
                  Receive alerts via Slack incoming webhook.
                </CardDescription>
              </div>
              <Switch
                checked={channels.slack_enabled}
                onCheckedChange={(checked) =>
                  setChannels((prev) => ({ ...prev, slack_enabled: checked }))
                }
              />
            </div>
          </CardHeader>
          {channels.slack_enabled && (
            <CardContent className="space-y-3">
              <div className="space-y-2">
                <Label htmlFor="slack_webhook_url" className="text-zinc-400 text-xs">
                  Webhook URL
                </Label>
                <Input
                  id="slack_webhook_url"
                  type="url"
                  value={channels.slack_webhook_url}
                  onChange={(e) =>
                    setChannels((prev) => ({
                      ...prev,
                      slack_webhook_url: e.target.value,
                    }))
                  }
                  placeholder="https://hooks.slack.com/services/T.../B.../..."
                  className="bg-zinc-950 border-zinc-800 text-zinc-100 focus:border-indigo-500 font-mono text-sm"
                />
              </div>
              <Button
                size="sm"
                variant="outline"
                onClick={handleTestSlack}
                disabled={testing === "slack"}
                className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
              >
                {testing === "slack" ? "Sending..." : "Send Test Message"}
              </Button>
            </CardContent>
          )}
        </Card>

        {/* Email */}
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-sm font-medium text-zinc-100">
                  Email
                </CardTitle>
                <CardDescription className="text-xs text-zinc-500 mt-1">
                  Receive alerts via email.
                </CardDescription>
              </div>
              <Switch
                checked={channels.email_enabled}
                onCheckedChange={(checked) =>
                  setChannels((prev) => ({ ...prev, email_enabled: checked }))
                }
              />
            </div>
          </CardHeader>
          {channels.email_enabled && (
            <CardContent>
              <div className="space-y-2">
                <Label htmlFor="email_address" className="text-zinc-400 text-xs">
                  Email Address
                </Label>
                <Input
                  id="email_address"
                  type="email"
                  value={channels.email_address}
                  onChange={(e) =>
                    setChannels((prev) => ({
                      ...prev,
                      email_address: e.target.value,
                    }))
                  }
                  placeholder="alerts@yourcompany.com"
                  className="bg-zinc-950 border-zinc-800 text-zinc-100 focus:border-indigo-500 text-sm"
                />
              </div>
            </CardContent>
          )}
        </Card>
      </div>

      <Separator className="bg-zinc-800" />

      {/* Notification Triggers */}
      <div className="space-y-4">
        <h2 className="text-lg font-medium text-zinc-200">Triggers</h2>
        <p className="text-sm text-zinc-500">
          Choose which events send notifications.
        </p>

        <Card className="bg-zinc-900 border-zinc-800">
          <CardContent className="pt-6 space-y-4">
            {triggerDefinitions.map((trigger) => (
              <div
                key={trigger.key}
                className="flex items-center justify-between py-2"
              >
                <div>
                  <p className="text-sm text-zinc-200">{trigger.label}</p>
                  <p className="text-xs text-zinc-500 mt-0.5">
                    {trigger.description}
                  </p>
                </div>
                <Switch
                  checked={triggers[trigger.key]}
                  onCheckedChange={(checked) =>
                    setTriggers((prev) => ({ ...prev, [trigger.key]: checked }))
                  }
                />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <Button
          onClick={handleSave}
          disabled={saving}
          className="bg-indigo-600 hover:bg-indigo-500 text-white"
        >
          {saving ? "Saving..." : "Save Notification Settings"}
        </Button>
      </div>
    </div>
  );
}
