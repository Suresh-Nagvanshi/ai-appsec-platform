/**
 * Reports service
 * ===============
 * Wraps the /report/generate backend endpoint.
 * Also re-exports listScans so the report page can populate a scan picker.
 */

import api from "@/lib/api";

// ── Response shapes from POST /report/generate ────────────────────────────

export interface AiAnalysis {
  summary?: string;
  attack_scenario?: string;
  business_impact?: string;
  secure_fix?: string;
  developer_remediation_steps?: string[];
  exploitability_score?: number | string;
  false_positive_probability?: string;
  priority_rank?: string | number;
}

export interface ReportFinding {
  id?: string;
  rule_id?: string;
  title?: string;
  severity?: string;
  path?: string;
  line?: number;
  risk_score?: number;
  cwe?: string;
  owasp?: string;
  mitre?: string;
  framework?: { primary_framework?: string };
  snippet?: { vulnerable_line?: string };
  ai_analysis?: AiAnalysis;
  // The backend may also return the raw finding wrapped under a "finding" key
  finding?: {
    rule_id?: string;
    severity?: string;
    path?: string;
    line?: number;
    message?: string;
  };
  error?: string;
}

export interface ReportSummary {
  total?: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  [key: string]: number | undefined;
}

export interface Report {
  scan_id: string;
  project_name?: string;
  scan_type?: string;
  summary?: ReportSummary;
  finding_count: number;
  findings: ReportFinding[];
  format?: string;
}

// ── API calls ──────────────────────────────────────────────────────────────

/** Generate (or fetch) a full report for a completed scan. */
export async function generateReport(scanId: string): Promise<Report> {
  const res = await api.post<Report>("/report/generate", {
    scan_id: scanId,
    format: "json",
  });
  return res.data;
}
