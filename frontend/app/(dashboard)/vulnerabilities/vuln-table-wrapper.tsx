"use client";

import { useRouter } from "next/navigation";
import { VulnTable, type Vulnerability } from "@/components/vulnerabilities/vuln-table";

interface VulnTableWrapperProps {
  vulnerabilities: Vulnerability[];
}

export function VulnTableWrapper({ vulnerabilities }: VulnTableWrapperProps) {
  const router = useRouter();

  function handleRowClick(vuln: Vulnerability) {
    router.push(`/vulnerabilities/${vuln.id}`);
  }

  return (
    <VulnTable vulnerabilities={vulnerabilities} onRowClick={handleRowClick} />
  );
}
