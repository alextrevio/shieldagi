import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

interface PlatformCreateBody {
  name: string;
  repo_url: string;
  domain?: string;
  github_token?: string;
  supabase_url?: string;
  supabase_anon_key?: string;
}

interface Platform {
  id: string;
  user_id: string;
  name: string;
  repo_url: string;
  domain: string | null;
  github_token: string | null;
  supabase_url: string | null;
  supabase_anon_key: string | null;
  status: "active" | "inactive" | "scanning";
  created_at: string;
  updated_at: string;
}

export async function GET() {
  try {
    const supabase = await createClient();

    const {
      data: { user },
      error: authError,
    } = await supabase.auth.getUser();

    if (authError || !user) {
      return NextResponse.json(
        { error: "Unauthorized" },
        { status: 401 }
      );
    }

    const { data: platforms, error } = await supabase
      .from("platforms")
      .select("*")
      .eq("user_id", user.id)
      .order("created_at", { ascending: false });

    if (error) {
      console.error("Failed to fetch platforms:", error);
      return NextResponse.json(
        { error: "Failed to fetch platforms" },
        { status: 500 }
      );
    }

    return NextResponse.json({ platforms: platforms || [] });
  } catch (error) {
    console.error("Unexpected error in GET /api/platforms:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const supabase = await createClient();

    const {
      data: { user },
      error: authError,
    } = await supabase.auth.getUser();

    if (authError || !user) {
      return NextResponse.json(
        { error: "Unauthorized" },
        { status: 401 }
      );
    }

    // Parse and validate request body
    let body: PlatformCreateBody;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        { error: "Invalid JSON body" },
        { status: 400 }
      );
    }

    if (!body.name || typeof body.name !== "string" || body.name.trim().length === 0) {
      return NextResponse.json(
        { error: "name is required" },
        { status: 400 }
      );
    }

    if (!body.repo_url || typeof body.repo_url !== "string") {
      return NextResponse.json(
        { error: "repo_url is required" },
        { status: 400 }
      );
    }

    // Validate repo_url format
    try {
      const url = new URL(body.repo_url);
      if (!["http:", "https:"].includes(url.protocol)) {
        return NextResponse.json(
          { error: "repo_url must be an HTTP or HTTPS URL" },
          { status: 400 }
        );
      }
    } catch {
      return NextResponse.json(
        { error: "repo_url must be a valid URL" },
        { status: 400 }
      );
    }

    // Validate domain if provided
    if (body.domain) {
      try {
        new URL(`https://${body.domain}`);
      } catch {
        return NextResponse.json(
          { error: "domain must be a valid hostname" },
          { status: 400 }
        );
      }
    }

    // Check for duplicate platform name for this user
    const { data: existing } = await supabase
      .from("platforms")
      .select("id")
      .eq("user_id", user.id)
      .eq("name", body.name.trim())
      .single();

    if (existing) {
      return NextResponse.json(
        { error: "A platform with this name already exists" },
        { status: 409 }
      );
    }

    // Insert the platform
    const { data: platform, error: insertError } = await supabase
      .from("platforms")
      .insert({
        user_id: user.id,
        name: body.name.trim(),
        repo_url: body.repo_url.trim(),
        domain: body.domain?.trim() || null,
        github_token: body.github_token?.trim() || null,
        supabase_url: body.supabase_url?.trim() || null,
        supabase_anon_key: body.supabase_anon_key?.trim() || null,
        status: "active",
      })
      .select("*")
      .single();

    if (insertError || !platform) {
      console.error("Failed to create platform:", insertError);
      return NextResponse.json(
        { error: "Failed to create platform" },
        { status: 500 }
      );
    }

    // Log the activity
    await supabase.from("activity_log").insert({
      user_id: user.id,
      action: "platform_connected",
      resource_type: "platform",
      resource_id: platform.id,
      metadata: {
        platform_name: platform.name,
        repo_url: platform.repo_url,
      },
    });

    return NextResponse.json({ platform }, { status: 201 });
  } catch (error) {
    console.error("Unexpected error in POST /api/platforms:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
