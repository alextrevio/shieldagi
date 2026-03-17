"use client";

import { useState, useEffect, useCallback } from "react";
import { createBrowserClient } from "@supabase/ssr";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface ApiKeyConfig {
  key: string;
  label: string;
  description: string;
  placeholder: string;
  configured: boolean;
  lastFour: string;
}

type ApiKeyName = "anthropic_api_key" | "github_token" | "supabase_url" | "supabase_anon_key" | "telegram_bot_token";

interface ApiKeyRecord {
  id: string;
  user_id: string;
  key_name: ApiKeyName;
  // Stored as-is for now; encryption is a TODO (see comment in handleSave)
  key_value: string;
  created_at: string;
  updated_at: string;
}

const KEY_DEFINITIONS: {
  key: ApiKeyName;
  label: string;
  description: string;
  placeholder: string;
}[] = [
  {
    key: "anthropic_api_key",
    label: "Anthropic API Key",
    description:
      "Used by OpenFang agents for AI-powered security analysis.",
    placeholder: "sk-ant-api03-...",
  },
  {
    key: "github_token",
    label: "GitHub Token",
    description:
      "Personal access token for repository scanning and remediation PRs.",
    placeholder: "ghp_...",
  },
  {
    key: "supabase_url",
    label: "Supabase URL",
    description:
      "Project URL for the target Supabase instance to scan.",
    placeholder: "https://your-project.supabase.co",
  },
  {
    key: "supabase_anon_key",
    label: "Supabase Anon Key",
    description:
      "Anonymous key for the target Supabase instance.",
    placeholder: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  },
  {
    key: "telegram_bot_token",
    label: "Telegram Bot Token",
    description: "Bot token for Telegram notifications.",
    placeholder: "123456789:ABCdefGhIJKlmNoPQRsTUVwxYZ",
  },
];

function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  );
}

export default function ApiKeysPage() {
  const [keys, setKeys] = useState<Map<ApiKeyName, ApiKeyRecord>>(new Map());
  const [editingKey, setEditingKey] = useState<ApiKeyName | null>(null);
  const [editValue, setEditValue] = useState("");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);
  const [loading, setLoading] = useState(true);

  const supabase = createClient();

  const loadKeys = useCallback(async () => {
    const {
      data: { user },
    } = await supabase.auth.getUser();
    if (!user) return;

    const { data, error } = await supabase
      .from("api_keys")
      .select("*")
      .eq("user_id", user.id);

    if (error) {
      setMessage({ type: "error", text: "Failed to load API keys." });
      setLoading(false);
      return;
    }

    const keyMap = new Map<ApiKeyName, ApiKeyRecord>();
    for (const record of data || []) {
      keyMap.set(record.key_name as ApiKeyName, record as ApiKeyRecord);
    }
    setKeys(keyMap);
    setLoading(false);
  }, [supabase]);

  useEffect(() => {
    loadKeys();
  }, [loadKeys]);

  const getLastFour = (value: string): string => {
    if (!value || value.length < 4) return "****";
    return value.slice(-4);
  };

  const handleStartEdit = (keyName: ApiKeyName) => {
    setEditingKey(keyName);
    setEditValue("");
    setMessage(null);
  };

  const handleCancelEdit = () => {
    setEditingKey(null);
    setEditValue("");
  };

  const handleSave = async (keyName: ApiKeyName) => {
    if (!editValue.trim()) {
      setMessage({ type: "error", text: "Please enter a value." });
      return;
    }

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

    const existing = keys.get(keyName);

    // TODO: Encrypt key_value before storing. Currently stored as plaintext.
    // Use a server-side encryption function or Supabase Vault for production.

    if (existing) {
      const { error } = await supabase
        .from("api_keys")
        .update({
          key_value: editValue.trim(),
          updated_at: new Date().toISOString(),
        })
        .eq("id", existing.id);

      if (error) {
        setMessage({ type: "error", text: `Failed to update ${keyName}.` });
        setSaving(false);
        return;
      }
    } else {
      const { error } = await supabase.from("api_keys").insert({
        user_id: user.id,
        key_name: keyName,
        key_value: editValue.trim(),
      });

      if (error) {
        setMessage({ type: "error", text: `Failed to save ${keyName}.` });
        setSaving(false);
        return;
      }
    }

    setMessage({ type: "success", text: "API key saved successfully." });
    setEditingKey(null);
    setEditValue("");
    setSaving(false);
    await loadKeys();
  };

  const handleRemove = async (keyName: ApiKeyName) => {
    const existing = keys.get(keyName);
    if (!existing) return;

    const { error } = await supabase
      .from("api_keys")
      .delete()
      .eq("id", existing.id);

    if (error) {
      setMessage({ type: "error", text: `Failed to remove ${keyName}.` });
      return;
    }

    setMessage({ type: "success", text: "API key removed." });
    await loadKeys();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="animate-pulse text-zinc-500">Loading API keys...</div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-8 p-6">
      <div>
        <h1 className="text-2xl font-semibold text-zinc-100">API Keys</h1>
        <p className="text-sm text-zinc-500 mt-1">
          Manage your API keys and credentials for integrations.
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

      <div className="space-y-4">
        {KEY_DEFINITIONS.map((def) => {
          const record = keys.get(def.key);
          const isConfigured = !!record;
          const isEditing = editingKey === def.key;

          return (
            <Card key={def.key} className="bg-zinc-900 border-zinc-800">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-sm font-medium text-zinc-100">
                      {def.label}
                    </CardTitle>
                    <CardDescription className="text-xs text-zinc-500 mt-1">
                      {def.description}
                    </CardDescription>
                  </div>
                  <Badge
                    className={
                      isConfigured
                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                        : "bg-zinc-700 text-zinc-400"
                    }
                  >
                    {isConfigured ? "Configured" : "Not configured"}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                {isEditing ? (
                  <div className="space-y-3">
                    <div className="space-y-2">
                      <Label
                        htmlFor={`key-${def.key}`}
                        className="text-zinc-400 text-xs"
                      >
                        {isConfigured ? "New value" : "Enter key"}
                      </Label>
                      <Input
                        id={`key-${def.key}`}
                        type="password"
                        value={editValue}
                        onChange={(e) => setEditValue(e.target.value)}
                        placeholder={def.placeholder}
                        className="bg-zinc-950 border-zinc-800 text-zinc-100 focus:border-indigo-500 focus:ring-indigo-500/20 font-mono text-sm"
                        autoFocus
                      />
                    </div>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        onClick={() => handleSave(def.key)}
                        disabled={saving}
                        className="bg-indigo-600 hover:bg-indigo-500 text-white"
                      >
                        {saving ? "Saving..." : "Save"}
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={handleCancelEdit}
                        className="text-zinc-400 hover:text-zinc-300 hover:bg-zinc-800"
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {isConfigured ? (
                        <span className="font-mono text-sm text-zinc-400">
                          {"*".repeat(20)}{getLastFour(record.key_value)}
                        </span>
                      ) : (
                        <span className="text-sm text-zinc-600">
                          No key configured
                        </span>
                      )}
                    </div>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleStartEdit(def.key)}
                        className="text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
                      >
                        {isConfigured ? "Update" : "Add"}
                      </Button>
                      {isConfigured && (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleRemove(def.key)}
                          className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
                        >
                          Remove
                        </Button>
                      )}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
