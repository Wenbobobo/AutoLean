import type { DashboardSnapshot } from "./types";

const configuredBase = import.meta.env?.VITE_API_URL;

/**
 * The browser dashboard has no credentials. Remote deployments use a same-origin
 * reverse proxy, so a build-time override may only select a loopback API origin.
 */
export function resolveApiBase(value: string | undefined): string {
  if (!value) return "";

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Dashboard API base must be empty or a loopback origin");
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    !["127.0.0.1", "localhost"].includes(url.hostname) ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    throw new Error("Dashboard API base must be empty or a loopback origin");
  }
  return url.origin;
}

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${resolveApiBase(configuredBase)}${path}`, {
    cache: "no-store",
    credentials: "omit",
    headers: { Accept: "application/json" },
    redirect: "error",
    referrerPolicy: "no-referrer"
  });
  if (!response.ok) {
    throw new Error(`Dashboard API request failed with status ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  snapshot: () => get<DashboardSnapshot>("/api/snapshot")
};
