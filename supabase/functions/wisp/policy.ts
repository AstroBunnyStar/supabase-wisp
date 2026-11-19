/**
 * Destination policy for the relay.
 *
 * A public relay is an open TCP/UDP proxy. Without a filter, anyone can use it
 * to reach private ranges or Supabase's own internal endpoints from inside
 * Supabase's network. These helpers keep the default posture closed and make
 * the allow/block lists easy to override with environment variables.
 */

const DEFAULT_BLOCKED = [
  "localhost",
  "*.localhost",
  "*.local",
  "*.internal",
  "*.home.arpa",
  "metadata.google.internal",
  "instance-data",
  // Supabase's own control plane / database endpoints are not relay targets.
  "*.supabase.co",
  "*.supabase.in",
  "*.supabase.red",
  "*.pooler.supabase.com",
];

export interface HostFilterOptions {
  /** Extra patterns to block, in addition to DEFAULT_BLOCKED. */
  blocked?: string[];
  /** If non-empty, only hosts matching one of these patterns are allowed. */
  allowed?: string[];
  /** Allow loopback / RFC1918 / link-local destinations (default false). */
  allowPrivate?: boolean;
}

export function splitList(value: string | null | undefined): string[] {
  if (!value) return [];
  return value
    .split(/[\s,]+/)
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry.length > 0);
}

/** Lowercase, trim, drop IPv6 brackets and any trailing root dot. */
export function normalizeHost(host: string): string {
  let normalized = host.trim().toLowerCase();
  if (normalized.startsWith("[") && normalized.endsWith("]")) {
    normalized = normalized.slice(1, -1);
  }
  while (normalized.endsWith(".")) normalized = normalized.slice(0, -1);
  return normalized;
}

export function matchesPattern(host: string, pattern: string): boolean {
  const normalizedHost = normalizeHost(host);
  const normalizedPattern = normalizeHost(pattern);
  if (normalizedPattern === "*") return true;
  if (normalizedPattern.startsWith("*.")) {
    const suffix = normalizedPattern.slice(1); // ".example.com"
    return normalizedHost.endsWith(suffix);
  }
  return normalizedHost === normalizedPattern;
}

export function isPrivateAddress(host: string): boolean {
  const normalized = normalizeHost(host);
  return normalized.includes(":")
    ? isPrivateIpv6(normalized)
    : isPrivateIpv4(normalized);
}

function isPrivateIpv4(host: string): boolean {
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    const value = Number(part);
    if (value > 255) return false;
    octets.push(value);
  }
  const [a, b] = octets;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true; // link-local / cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 192 && b === 0) return true; // 192.0.0.0/16 incl. test nets
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a >= 224) return true; // multicast + reserved
  return false;
}

function isPrivateIpv6(host: string): boolean {
  if (host === "::" || host === "::1") return true;
  if (/^f[cd][0-9a-f]{2}:/.test(host)) return true; // fc00::/7 unique local
  if (/^fe[89ab][0-9a-f]:/.test(host)) return true; // fe80::/10 link-local
  if (/^ff[0-9a-f]{2}:/.test(host)) return true; // multicast
  const mapped = host.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mapped) return isPrivateIpv4(mapped[1]);
  return false;
}

/**
 * Build a predicate: true = the destination may be relayed.
 *
 * Note: this inspects the requested hostname, not the resolved address, so a
 * name that resolves to a private address after the check (DNS rebinding) is a
 * known limitation. Keep WISP_ALLOWED_HOSTS tight for a public deployment.
 */
export function createHostFilter(
  options: HostFilterOptions = {},
): (host: string) => boolean {
  const allowPrivate = options.allowPrivate ?? false;
  const blocked = [...DEFAULT_BLOCKED, ...(options.blocked ?? [])];
  const allowed = (options.allowed ?? []).filter((entry) => entry.length > 0);

  return (host: string): boolean => {
    const normalized = normalizeHost(host);
    if (normalized.length === 0) return false;

    if (allowed.length > 0) {
      const matchesAllowList = allowed.some((pattern) =>
        matchesPattern(normalized, pattern)
      );
      if (!matchesAllowList) return false;
    }

    if (!allowPrivate && isPrivateAddress(normalized)) return false;

    for (const pattern of blocked) {
      if (matchesPattern(normalized, pattern)) return false;
    }
    return true;
  };
}
