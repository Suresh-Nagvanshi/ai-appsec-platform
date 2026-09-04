/**
 * Website Security service
 * ========================
 * Wraps all /api/website-scans/* backend endpoints.
 */

import api from "@/lib/api";

export interface WebsiteScanFinding {
  id: string;
  url: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  category: string;
  title: string;
  description: string;
  evidence?: string;
  recommendation?: string;
  discovered_at: string;
}

export interface WebsiteScan {
  id: string;
  scanType: "website";
  target: string;
  max_pages: number;
  max_depth: number;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  progress: number;
  startedAt: string;
  completedAt: string | null;
  duration: string | null;
  pagesScanned: number;
  findingsCount: number;
  criticalCount: number;
  summary: Record<string, number>;
  logs: Array<{ id: string; time: string; level: string; message: string }>;
  timeline: Array<{ id: string; name: string; status: string }>;
  failureReason: string | null;
  findings: WebsiteScanFinding[];
}

/** Start a website security scan. Returns scan_id. */
export async function startWebsiteScan(
  url: string,
  maxPages = 20,
  maxDepth = 3
): Promise<string> {
  const res = await api.post<{ scan_id: string; status: string; target: string }>(
    "/api/website-scans",
    { url, max_pages: maxPages, max_depth: maxDepth }
  );
  return res.data.scan_id;
}

/** Get single website scan (live progress). */
export async function getWebsiteScan(scanId: string): Promise<WebsiteScan> {
  const res = await api.get<WebsiteScan>(`/api/website-scans/${scanId}`);
  return res.data;
}

/** List all website scans, newest first. */
export async function listWebsiteScans(): Promise<WebsiteScan[]> {
  const res = await api.get<WebsiteScan[]>("/api/website-scans");
  return res.data;
}
