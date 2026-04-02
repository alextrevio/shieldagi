import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

interface ScanRequestBody {
  platform_id: string;
  type: "full" | "quick" | "targeted";
  target_vectors?: string[];
}

interface ScanRecord {
  id: string;
  platform_id: string;
  user_id: string;
  type: string;
  status: "queued" | "running" | "completed" | "failed";
  target_vectors: string[] | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

interface OpenFangAgentPayload {
  message: string;
  context: {
    scan_id: string;
    platform_id: string;
    type: string;
    target_vectors: string[] | null;
  };
}

export async function POST(request: NextRequest) {
  try {
    const supabase = await createClient();

    // Authenticate the user
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
    let body: ScanRequestBody;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        { error: "Invalid JSON body" },
        { status: 400 }
      );
    }

    if (!body.platform_id || typeof body.platform_id !== "string") {
      return NextResponse.json(
        { error: "platform_id is required and must be a string" },
        { status: 400 }
      );
    }

    const validTypes = ["full", "quick", "targeted"];
    if (!body.type || !validTypes.includes(body.type)) {
      return NextResponse.json(
        { error: `type must be one of: ${validTypes.join(", ")}` },
        { status: 400 }
      );
    }

    if (body.type === "targeted" && (!body.target_vectors || body.target_vectors.length === 0)) {
      return NextResponse.json(
        { error: "target_vectors is required for targeted scans" },
        { status: 400 }
      );
    }

    // Verify the platform belongs to the authenticated user
    const { data: platform, error: platformError } = await supabase
      .from("platforms")
      .select("id, name, repo_url, supabase_url, supabase_anon_key")
      .eq("id", body.platform_id)
      .eq("user_id", user.id)
      .single();

    if (platformError || !platform) {
      return NextResponse.json(
        { error: "Platform not found or access denied" },
        { status: 404 }
      );
    }

    // Create the scan record
    const { data: scan, error: scanError } = await supabase
      .from("scans")
      .insert({
        platform_id: body.platform_id,
        user_id: user.id,
        type: body.type,
        status: "queued",
        target_vectors: body.target_vectors || null,
      })
      .select("id, status, created_at")
      .single();

    if (scanError || !scan) {
      console.error("Failed to create scan record:", scanError);
      return NextResponse.json(
        { error: "Failed to create scan" },
        { status: 500 }
      );
    }

    // Log the activity
    await supabase.from("activity_log").insert({
      user_id: user.id,
      action: "scan_started",
      resource_type: "scan",
      resource_id: scan.id,
      metadata: {
        platform_id: body.platform_id,
        platform_name: platform.name,
        scan_type: body.type,
        target_vectors: body.target_vectors || null,
      },
    });

    // Spawn the scan agent via OpenFang API
    const openfangUrl = process.env.OPENFANG_API_URL;
    if (openfangUrl) {
      const agentPayload: OpenFangAgentPayload = {
        message: `Run a ${body.type} security scan on platform "${platform.name}"`,
        context: {
          scan_id: scan.id,
          platform_id: body.platform_id,
          type: body.type,
          target_vectors: body.target_vectors || null,
        },
      };

      try {
        const agentResponse = await fetch(
          `${openfangUrl}/api/agents/recon-scout/chat`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${process.env.OPENFANG_API_KEY || ""}`,
            },
            body: JSON.stringify(agentPayload),
          }
        );

        if (!agentResponse.ok) {
          console.error(
            "OpenFang agent spawn failed:",
            agentResponse.status,
            await agentResponse.text()
          );
          // Don't fail the scan creation; mark it as queued and let retry handle it
          await supabase
            .from("scans")
            .update({
              status: "queued",
              metadata: { agent_spawn_error: true },
            })
            .eq("id", scan.id);
        }
      } catch (fetchError) {
        console.error("Failed to reach OpenFang API:", fetchError);
        // Scan is still created and queued; OpenFang may pick it up later
      }
    } else {
      console.warn("OPENFANG_API_URL not configured; scan queued but no agent spawned.");
    }

    return NextResponse.json(
      {
        scan_id: scan.id,
        status: "queued",
        created_at: scan.created_at,
      },
      { status: 201 }
    );
  } catch (error) {
    console.error("Unexpected error in POST /api/scan:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
