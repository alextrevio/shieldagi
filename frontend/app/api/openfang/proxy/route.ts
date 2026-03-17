import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

interface ProxyRequestBody {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  body?: Record<string, unknown>;
}

const ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];

// Paths that are never proxied for security reasons
const BLOCKED_PATHS = [
  "/api/admin",
  "/api/internal",
  "/api/config",
];

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
    let proxyRequest: ProxyRequestBody;
    try {
      proxyRequest = await request.json();
    } catch {
      return NextResponse.json(
        { error: "Invalid JSON body" },
        { status: 400 }
      );
    }

    // Validate method
    if (!proxyRequest.method || !ALLOWED_METHODS.includes(proxyRequest.method)) {
      return NextResponse.json(
        { error: `method must be one of: ${ALLOWED_METHODS.join(", ")}` },
        { status: 400 }
      );
    }

    // Validate path
    if (!proxyRequest.path || typeof proxyRequest.path !== "string") {
      return NextResponse.json(
        { error: "path is required" },
        { status: 400 }
      );
    }

    // Ensure path starts with /
    const normalizedPath = proxyRequest.path.startsWith("/")
      ? proxyRequest.path
      : `/${proxyRequest.path}`;

    // Block sensitive paths
    if (BLOCKED_PATHS.some((blocked) => normalizedPath.startsWith(blocked))) {
      return NextResponse.json(
        { error: "Access to this path is not allowed" },
        { status: 403 }
      );
    }

    // Prevent path traversal
    if (normalizedPath.includes("..") || normalizedPath.includes("//")) {
      return NextResponse.json(
        { error: "Invalid path" },
        { status: 400 }
      );
    }

    // Build the target URL
    const openfangUrl = process.env.OPENFANG_API_URL;
    if (!openfangUrl) {
      return NextResponse.json(
        { error: "OpenFang API is not configured" },
        { status: 503 }
      );
    }

    const targetUrl = `${openfangUrl.replace(/\/+$/, "")}${normalizedPath}`;

    // Build fetch options
    const fetchOptions: RequestInit = {
      method: proxyRequest.method,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.OPENFANG_API_KEY || ""}`,
        "X-ShieldAGI-User": user.id,
        "X-ShieldAGI-Email": user.email || "",
      },
    };

    // Include body for non-GET requests
    if (proxyRequest.method !== "GET" && proxyRequest.body) {
      fetchOptions.body = JSON.stringify(proxyRequest.body);
    }

    // Forward the request to OpenFang
    let openfangResponse: Response;
    try {
      openfangResponse = await fetch(targetUrl, fetchOptions);
    } catch (fetchError) {
      console.error("Failed to reach OpenFang API:", fetchError);
      return NextResponse.json(
        { error: "Failed to connect to OpenFang API" },
        { status: 502 }
      );
    }

    // Parse the response
    let responseData: unknown;
    const contentType = openfangResponse.headers.get("content-type") || "";

    if (contentType.includes("application/json")) {
      try {
        responseData = await openfangResponse.json();
      } catch {
        responseData = { message: "Response could not be parsed as JSON" };
      }
    } else {
      const text = await openfangResponse.text();
      responseData = { message: text };
    }

    // Return the OpenFang response with its status code
    return NextResponse.json(responseData, {
      status: openfangResponse.status,
      headers: {
        "X-OpenFang-Status": String(openfangResponse.status),
      },
    });
  } catch (error) {
    console.error("Unexpected error in POST /api/openfang/proxy:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
