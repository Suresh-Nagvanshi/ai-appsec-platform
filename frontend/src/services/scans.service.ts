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
}

/** Start a GitHub repository scan. Returns scan_id. */
export async function startGithubScan(repoUrl: string): Promise<string> {
  const form = new FormData();
  form.append("repo_url", repoUrl);
  const res = await api.post<{ scan_id: string; status: string }>(
    "/api/scans/github",
    form,
    { headers: { "Content-Type": "multipart/form-data" } }
  );
  return res.data.scan_id;
}

/** Start a ZIP upload scan. Returns scan_id. */
export async function startZipScan(file: File): Promise<string> {
  const form = new FormData();
  form.append("file", file);
  const res = await api.post<{ scan_id: string; status: string }>(
    "/api/scans/zip",
    form,
    { headers: { "Content-Type": "multipart/form-data" } }
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
