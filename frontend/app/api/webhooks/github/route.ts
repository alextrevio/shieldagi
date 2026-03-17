import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

interface PullRequestEvent {
  action: string;
  pull_request: {
    id: number;
    number: number;
    title: string;
    merged: boolean;
    merged_at: string | null;
    head: {
      ref: string;
      sha: string;
    };
    base: {
      ref: string;
    };
    body: string | null;
  };
  repository: {
    full_name: string;
    html_url: string;
  };
}

async function verifyWebhookSignature(
  request: NextRequest,
  rawBody: string
): Promise<boolean> {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) {
    console.error("GITHUB_WEBHOOK_SECRET is not configured");
    return false;
  }

  const signature = request.headers.get("x-hub-signature-256");
  if (!signature) {
    return false;
  }

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(rawBody)
  );

  const computedSignature =
    "sha256=" +
    Array.from(new Uint8Array(signatureBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

  // Constant-time comparison
  if (computedSignature.length !== signature.length) {
    return false;
  }

  let mismatch = 0;
  for (let i = 0; i < computedSignature.length; i++) {
    mismatch |= computedSignature.charCodeAt(i) ^ signature.charCodeAt(i);
  }

  return mismatch === 0;
}

/**
 * Extract the ShieldAGI remediation ID from a PR body or branch name.
 * Convention: PR body contains a line like `shieldagi-remediation-id: <uuid>`
 * or the branch name starts with `shieldagi/remediate-<uuid>`.
 */
function extractRemediationId(event: PullRequestEvent): string | null {
  // Check PR body for remediation ID tag
  const body = event.pull_request.body || "";
  const bodyMatch = body.match(/shieldagi-remediation-id:\s*([a-f0-9-]+)/i);
  if (bodyMatch) {
    return bodyMatch[1];
  }

  // Check branch name
  const branchRef = event.pull_request.head.ref;
  const branchMatch = branchRef.match(/^shieldagi\/remediate-([a-f0-9-]+)/);
  if (branchMatch) {
    return branchMatch[1];
  }

  return null;
}

export async function POST(request: NextRequest) {
  try {
    // Read raw body for signature verification
    const rawBody = await request.text();

    // Verify the webhook signature
    const isValid = await verifyWebhookSignature(request, rawBody);
    if (!isValid) {
      return NextResponse.json(
        { error: "Invalid webhook signature" },
        { status: 401 }
      );
    }

    // Parse the event
    let event: PullRequestEvent;
    try {
      event = JSON.parse(rawBody);
    } catch {
      return NextResponse.json(
        { error: "Invalid JSON payload" },
        { status: 400 }
      );
    }

    const eventType = request.headers.get("x-github-event");

    // We only handle pull_request events
    if (eventType !== "pull_request") {
      return NextResponse.json({ message: "Event type not handled" }, { status: 200 });
    }

    const supabase = await createClient();
    const remediationId = extractRemediationId(event);

    // If we can't find a remediation ID, this PR isn't related to ShieldAGI
    if (!remediationId) {
      return NextResponse.json(
        { message: "Not a ShieldAGI remediation PR" },
        { status: 200 }
      );
    }

    if (event.action === "closed" && event.pull_request.merged) {
      // PR was merged — remediation applied successfully
      const { error: updateError } = await supabase
        .from("remediations")
        .update({
          status: "merged",
          merged_at: event.pull_request.merged_at,
          pr_number: event.pull_request.number,
          updated_at: new Date().toISOString(),
        })
        .eq("id", remediationId);

      if (updateError) {
        console.error("Failed to update remediation status:", updateError);
        return NextResponse.json(
          { error: "Failed to update remediation" },
          { status: 500 }
        );
      }

      // Update associated vulnerabilities to 'fixed'
      const { data: remediation } = await supabase
        .from("remediations")
        .select("vulnerability_ids")
        .eq("id", remediationId)
        .single();

      if (remediation?.vulnerability_ids && Array.isArray(remediation.vulnerability_ids)) {
        const { error: vulnError } = await supabase
          .from("vulnerabilities")
          .update({
            status: "fixed",
            fixed_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          })
          .in("id", remediation.vulnerability_ids);

        if (vulnError) {
          console.error("Failed to update vulnerability statuses:", vulnError);
        }
      }

      // Log the activity
      await supabase.from("activity_log").insert({
        action: "remediation_merged",
        resource_type: "remediation",
        resource_id: remediationId,
        metadata: {
          pr_number: event.pull_request.number,
          repository: event.repository.full_name,
          merged_at: event.pull_request.merged_at,
        },
      });

      return NextResponse.json({ message: "Remediation marked as merged" }, { status: 200 });
    }

    if (event.action === "closed" && !event.pull_request.merged) {
      // PR was closed without merging — remediation rejected
      const { error: updateError } = await supabase
        .from("remediations")
        .update({
          status: "rejected",
          pr_number: event.pull_request.number,
          updated_at: new Date().toISOString(),
        })
        .eq("id", remediationId);

      if (updateError) {
        console.error("Failed to update remediation status:", updateError);
        return NextResponse.json(
          { error: "Failed to update remediation" },
          { status: 500 }
        );
      }

      // Log the activity
      await supabase.from("activity_log").insert({
        action: "remediation_rejected",
        resource_type: "remediation",
        resource_id: remediationId,
        metadata: {
          pr_number: event.pull_request.number,
          repository: event.repository.full_name,
        },
      });

      return NextResponse.json({ message: "Remediation marked as rejected" }, { status: 200 });
    }

    // Other PR actions (opened, synchronize, etc.) — acknowledge but don't act
    return NextResponse.json({ message: "Event acknowledged" }, { status: 200 });
  } catch (error) {
    console.error("Unexpected error in POST /api/webhooks/github:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
