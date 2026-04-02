import { ConnectForm } from "@/components/platforms/connect-form";

export default function NewPlatformPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Connect Platform</h1>
        <p className="text-sm text-zinc-500 mt-1">Connect a GitHub repository to scan for vulnerabilities and apply automated fixes.</p>
      </div>
      <ConnectForm />
    </div>
  );
}
