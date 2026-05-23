/**
 * Findings service
 * ================
 * Wraps all /findings/* backend endpoints.
 * Returns real data from FindingsRepository (no mock data).
 */

import api from "@/lib/api";

export interface Finding {
  id: string;
  scan_id: string;
  status: "open" | "in_progress" | "resolved" | "false_positive";
  severity?: string;
  [key: string]: unknown;
}

export interface FindingsResponse {
  total: number;
  offset: number;
  limit: number;
  findings: Finding[];
}

/** List findings with optional filters. */
export async function getFindings(params?: {
  scan_id?: string;
  severity?: string;
  status?: string;
  limit?: number;
  offset?: number;
}): Promise<FindingsResponse> {
  const res = await api.get<FindingsResponse>("/findings", { params });
  return res.data;
}

/** Get a single finding by id. */
export async function getFinding(findingId: string): Promise<Finding> {
  const res = await api.get<Finding>(`/findings/${findingId}`);
  return res.data;
}

/** Update the triage status of a finding. */
export async function updateFindingStatus(
  findingId: string,
  status: Finding["status"]
): Promise<void> {
  await api.patch(`/findings/${findingId}/status`, { status });
}
