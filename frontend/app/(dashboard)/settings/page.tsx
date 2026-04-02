"use client";

import { useState, useEffect, useCallback } from "react";
import { createBrowserClient } from "@supabase/ssr";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";

type Theme = "dark" | "light" | "system";

interface Profile {
  id: string;
  full_name: string;
  email: string;
  company: string;
  plan: "free" | "pro" | "enterprise";
  theme: Theme;
}

function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  );
}

export default function SettingsPage() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [fullName, setFullName] = useState("");
  const [company, setCompany] = useState("");
  const [theme, setTheme] = useState<Theme>("dark");
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [message, setMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  const supabase = createClient();

  const loadProfile = useCallback(async () => {
    const {
      data: { user },
      error: authError,
    } = await supabase.auth.getUser();
    if (authError || !user) return;

    const { data, error } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", user.id)
      .single();

    if (error) {
      // Profile doesn't exist yet — create a default one
      if (error.code === "PGRST116") {
        const defaultProfile: Profile = {
          id: user.id,
          full_name: user.user_metadata?.full_name || "",
          email: user.email || "",
          company: "",
          plan: "free",
          theme: "dark",
        };
        await supabase.from("profiles").insert({
          id: user.id,
          full_name: defaultProfile.full_name,
          company: "",
          plan: "free",
          theme: "dark",
        });
        setProfile(defaultProfile);
        setFullName(defaultProfile.full_name);
        setCompany("");
        setTheme("dark");
      }
      return;
    }

    const p: Profile = {
      id: data.id,
      full_name: data.full_name || "",
      email: user.email || "",
      company: data.company || "",
      plan: data.plan || "free",
      theme: data.theme || "dark",
    };
    setProfile(p);
    setFullName(p.full_name);
    setCompany(p.company);
    setTheme(p.theme);
  }, [supabase]);

  useEffect(() => {
    loadProfile();
  }, [loadProfile]);

  const handleSave = async () => {
    if (!profile) return;
    setSaving(true);
    setMessage(null);

    const { error } = await supabase
      .from("profiles")
      .update({
        full_name: fullName,
        company,
        theme,
        updated_at: new Date().toISOString(),
      })
      .eq("id", profile.id);

    if (error) {
      setMessage({ type: "error", text: "Failed to save settings." });
    } else {
      setMessage({ type: "success", text: "Settings saved successfully." });
      // Apply theme
      if (theme === "dark") {
        document.documentElement.classList.add("dark");
        document.documentElement.classList.remove("light");
      } else if (theme === "light") {
        document.documentElement.classList.remove("dark");
        document.documentElement.classList.add("light");
      } else {
        const prefersDark = window.matchMedia(
          "(prefers-color-scheme: dark)"
        ).matches;
        document.documentElement.classList.toggle("dark", prefersDark);
        document.documentElement.classList.toggle("light", !prefersDark);
      }
    }

    setSaving(false);
  };

  const handleDeleteAccount = async () => {
    if (!profile) return;
    setDeleting(true);

    // Delete profile data, then sign out.
    // Actual user deletion requires a server-side admin call;
    // here we mark the account as deleted and sign out.
    const { error } = await supabase
      .from("profiles")
      .update({ deleted_at: new Date().toISOString() })
      .eq("id", profile.id);

    if (error) {
      setMessage({ type: "error", text: "Failed to delete account." });
      setDeleting(false);
      return;
    }

    await supabase.auth.signOut();
    window.location.href = "/login";
  };

  const planColors: Record<string, string> = {
    free: "bg-zinc-700 text-zinc-300",
    pro: "bg-indigo-600/20 text-indigo-400 border border-indigo-500/30",
    enterprise:
      "bg-amber-600/20 text-amber-400 border border-amber-500/30",
  };

  if (!profile) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="animate-pulse text-zinc-500">Loading settings...</div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-8 p-6">
      <div>
        <h1 className="text-2xl font-semibold text-zinc-100">Settings</h1>
        <p className="text-sm text-zinc-500 mt-1">
          Manage your account settings and preferences.
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

      {/* Profile Section */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-zinc-100">Profile</CardTitle>
          <CardDescription className="text-zinc-500">
            Your personal information.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="fullName" className="text-zinc-400">
              Full Name
            </Label>
            <Input
              id="fullName"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="bg-zinc-950 border-zinc-800 text-zinc-100 focus:border-indigo-500 focus:ring-indigo-500/20"
              placeholder="Your full name"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="email" className="text-zinc-400">
              Email
            </Label>
            <Input
              id="email"
              value={profile.email}
              readOnly
              disabled
              className="bg-zinc-950 border-zinc-800 text-zinc-500 cursor-not-allowed"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="company" className="text-zinc-400">
              Company
            </Label>
            <Input
              id="company"
              value={company}
              onChange={(e) => setCompany(e.target.value)}
              className="bg-zinc-950 border-zinc-800 text-zinc-100 focus:border-indigo-500 focus:ring-indigo-500/20"
              placeholder="Your company name"
            />
          </div>
        </CardContent>
      </Card>

      {/* Plan Section */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-zinc-100">Plan</CardTitle>
          <CardDescription className="text-zinc-500">
            Your current subscription plan.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-3">
            <span className="text-zinc-300">Current plan:</span>
            <Badge
              className={`${
                planColors[profile.plan]
              } capitalize font-medium`}
            >
              {profile.plan}
            </Badge>
          </div>
        </CardContent>
      </Card>

      {/* Theme Section */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-zinc-100">Appearance</CardTitle>
          <CardDescription className="text-zinc-500">
            Customize how ShieldAGI looks on your device.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <Label htmlFor="theme" className="text-zinc-400">
              Theme
            </Label>
            <Select value={theme} onValueChange={(v) => setTheme(v as Theme)}>
              <SelectTrigger className="w-[200px] bg-zinc-950 border-zinc-800 text-zinc-100">
                <SelectValue placeholder="Select theme" />
              </SelectTrigger>
              <SelectContent className="bg-zinc-900 border-zinc-800">
                <SelectItem value="dark" className="text-zinc-100">
                  Dark
                </SelectItem>
                <SelectItem value="light" className="text-zinc-100">
                  Light
                </SelectItem>
                <SelectItem value="system" className="text-zinc-100">
                  System
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Save Button */}
      <div className="flex justify-end">
        <Button
          onClick={handleSave}
          disabled={saving}
          className="bg-indigo-600 hover:bg-indigo-500 text-white"
        >
          {saving ? "Saving..." : "Save Changes"}
        </Button>
      </div>

      <Separator className="bg-zinc-800" />

      {/* Danger Zone */}
      <Card className="bg-zinc-900 border-red-900/50">
        <CardHeader>
          <CardTitle className="text-red-400">Danger Zone</CardTitle>
          <CardDescription className="text-zinc-500">
            Irreversible actions for your account.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-zinc-300">Delete account</p>
              <p className="text-xs text-zinc-500 mt-1">
                Permanently delete your account and all associated data.
              </p>
            </div>
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button
                  variant="destructive"
                  className="bg-red-600/10 text-red-400 border border-red-500/30 hover:bg-red-600/20"
                >
                  Delete Account
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent className="bg-zinc-900 border-zinc-800">
                <AlertDialogHeader>
                  <AlertDialogTitle className="text-zinc-100">
                    Are you absolutely sure?
                  </AlertDialogTitle>
                  <AlertDialogDescription className="text-zinc-400">
                    This action cannot be undone. This will permanently delete
                    your account and remove all of your data from our servers,
                    including all platforms, scan results, and configurations.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel className="bg-zinc-800 border-zinc-700 text-zinc-300 hover:bg-zinc-700">
                    Cancel
                  </AlertDialogCancel>
                  <AlertDialogAction
                    onClick={handleDeleteAccount}
                    disabled={deleting}
                    className="bg-red-600 hover:bg-red-500 text-white"
                  >
                    {deleting ? "Deleting..." : "Yes, delete my account"}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
