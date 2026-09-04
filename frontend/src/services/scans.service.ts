/**
 * Scans service
 * =============
 * Wraps all /api/scans/* backend endpoints.
 * Replaces the localStorage-based simulation.
 */

import api from "@/lib/api";

export interface ScanRecord {
  id: string;
  scanType: "github" | "zip";
  target: string;
  branch: string | null;
  commit: string | null;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  progress: number;
  startedAt: string;
  completedAt: string | null;
  duration: string | null;
  findingsCount: number;
  criticalCount: number;
  summary: Record<string, number>;
  logs: Array<{ id: string; time: string; level: string; message: string }>;
  timeline: Array<{ id: string; name: string; status: string }>;
  failureReason: string | null;
  diff_info?: DiffInfo;
}

export interface DiffInfo {
  changed_files: string[];
  base_commit: string;
  current_commit: string;
  added: number;
  modified: number;
  deleted: number;
  total_changed: number;
}

/** Start a GitHub repository scan. Returns scan_id. */
export async function startGithubScan(
  repoUrl: string,
  branch?: string
): Promise<string> {
  // Backend expects application/json with { repo_url, branch? } — axios default.
  const res = await api.post<{ scan_id: string; status: string; branch?: string }>(
    "/api/scans/github",
    { repo_url: repoUrl, branch: branch || undefined }
  );
  return res.data.scan_id;
}

/** Start an incremental GitHub scan against a base scan (diff only). */
export async function startIncrementalScan(
  repoUrl: string,
  baseScanId: string,
  branch?: string
): Promise<string> {
  const res = await api.post<{ scan_id: string }>("/api/scans/github", {
    repo_url: repoUrl,
    branch: branch || undefined,
    base_scan_id: baseScanId,
  });
  return res.data.scan_id;
}

/** Start a ZIP upload scan. Returns scan_id. */
export async function startZipScan(file: File): Promise<string> {
  // File uploads must remain multipart/form-data.
  const form = new FormData();
  form.append("file", file);
  const res = await api.post<{ scan_id: string; status: string }>(
    "/api/scans/zip",
    form
  );
  return res.data.scan_id;
}

/** Fetch a single scan record (live progress). */
export async function getScan(scanId: string): Promise<ScanRecord> {
  const res = await api.get<ScanRecord>(`/api/scans/${scanId}`);
  return res.data;
}

/** List all scans, newest first. */
export async function listScans(): Promise<ScanRecord[]> {
  const res = await api.get<ScanRecord[]>("/api/scans");
  return res.data;
}

/** Fetch diff info for an incremental scan. */
export async function getScanDiff(scanId: string): Promise<DiffInfo> {
  const res = await api.get<DiffInfo>(`/api/scans/${scanId}/diff`);
  return res.data;
}
