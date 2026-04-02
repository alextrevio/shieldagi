import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { Sidebar } from "@/components/layout/sidebar";
import { MobileNav } from "@/components/layout/mobile-nav";

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) redirect("/login");

  return (
    <div className="min-h-screen bg-surface">
      <Sidebar userEmail={user.email} />
      <div className="lg:pl-60 flex flex-col min-h-screen">
        <div className="lg:hidden flex items-center h-14 px-4 border-b border-border bg-surface">
          <MobileNav />
          <span className="ml-2 text-sm font-semibold text-zinc-200">ShieldAGI</span>
        </div>
        <main className="flex-1 p-6">{children}</main>
      </div>
    </div>
  );
}
