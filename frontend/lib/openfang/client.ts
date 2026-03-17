const OPENFANG_URL = process.env.OPENFANG_API_URL || "http://127.0.0.1:4200";

export class OpenFangClient {
  private baseUrl: string;

  constructor(baseUrl?: string) {
    this.baseUrl = baseUrl || OPENFANG_URL;
  }

  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options?.headers,
      },
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "Unknown error");
      throw new Error(`OpenFang API error ${res.status}: ${text}`);
    }

    return res.json();
  }

  async getHealth(): Promise<{ status: string }> {
    return this.request("/health");
  }

  async listAgents(): Promise<{ agents: Array<{ name: string; status: string }> }> {
    return this.request("/api/agents");
  }

  async chatWithAgent(agentName: string, message: string): Promise<{ response: string }> {
    return this.request(`/api/agents/${agentName}/chat`, {
      method: "POST",
      body: JSON.stringify({ message }),
    });
  }

  async listHands(): Promise<{ hands: Array<{ name: string; status: string; schedule: string }> }> {
    return this.request("/api/hands");
  }

  async activateHand(handName: string): Promise<{ status: string }> {
    return this.request(`/api/hands/${handName}/activate`, {
      method: "POST",
    });
  }
}

export const openfang = new OpenFangClient();
