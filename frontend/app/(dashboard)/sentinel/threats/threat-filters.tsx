"use client";

import { useRouter } from "next/navigation";

interface SearchParams {
  severity?: string;
  platform?: string;
  from?: string;
  to?: string;
  page?: string;
}

function buildSearchUrl(
  params: SearchParams,
  overrides: Record<string, string>
): string {
  const merged = { ...params, ...overrides };
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(merged)) {
    if (value) search.set(key, value);
  }
  const qs = search.toString();
  return `/sentinel/threats${qs ? `?${qs}` : ""}`;
}

export function ThreatFilterSelect({
  name,
  value,
  options,
  params,
}: {
  name: string;
  value: string;
  options: Array<{ value: string; label: string }>;
  params: SearchParams;
}) {
  const router = useRouter();

  return (
    <select
      defaultValue={value}
      className="rounded-lg border border-[#1F1F22] bg-[#141415] px-3 py-1.5 text-xs text-zinc-300 focus:outline-none focus:ring-1 focus:ring-zinc-600 appearance-none pr-8 cursor-pointer"
      onChange={(e) => {
        const url = buildSearchUrl(params, {
          [name]: e.target.value,
          page: "",
        });
        router.push(url);
      }}
    >
      {options.map((opt) => (
        <option key={opt.value} value={opt.value}>
          {opt.label}
        </option>
      ))}
    </select>
  );
}

export function ThreatFilterInput({
  name,
  type,
  value,
  params,
}: {
  name: string;
  type: string;
  value: string;
  params: SearchParams;
}) {
  const router = useRouter();

  return (
    <input
      type={type}
      defaultValue={value}
      className="rounded-lg border border-[#1F1F22] bg-[#141415] px-3 py-1.5 text-xs text-zinc-300 focus:outline-none focus:ring-1 focus:ring-zinc-600"
      onChange={(e) => {
        const url = buildSearchUrl(params, {
          [name]: e.target.value,
          page: "",
        });
        router.push(url);
      }}
    />
  );
}
