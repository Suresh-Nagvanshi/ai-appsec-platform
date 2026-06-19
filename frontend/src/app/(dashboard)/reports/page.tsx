/**
 * Reports Page  /reports
 * =======================
 * Full implementation replacing the blank stub.
 *
 * Flow:
 *   1. Dropdown is populated with all COMPLETED scans (GET /api/scans)
 *   2. User selects a scan → clicks "Generate Report"
 *   3. POST /report/generate is called; spinner shown during generation
 *   4. Report renders:
 *        • Header card  — project name, scan type, scan_id, finding count
 *        • Severity summary  — Critical / High / Medium / Low pills
 *        • Findings table  — each row expandable into AI detail accordion
 *   5. "Export JSON" button lets user download the raw report payload
 *
 * Fix: report.findings guarded with ?? [] on both .length and .map() calls
 *      so a missing/undefined findings key never crashes the render.
 */

"use client";

import React, { useState } from "react";
import { useGenerateReport, useScansForPicker } from "@/hooks/use-report";
import type { Report, ReportFinding } from "@/services/reports.service";

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

const SEV_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-900/40 text-red-300 border-red-700",
  HIGH:     "bg-orange-900/40 text-orange-300 border-orange-700",
  MEDIUM:   "bg-yellow-900/40 text-yellow-300 border-yellow-700",
  LOW:      "bg-zinc-800 text-zinc-300 border-zinc-600",
  INFO:     "bg-blue-900/40 text-blue-300 border-blue-700",
};

function sevStyle(sev?: string) {
  return SEV_STYLES[(sev ?? "").toUpperCase()] ?? SEV_STYLES.LOW;
}

function SevBadge({ severity }: { severity?: string }) {
  return (
    <span
      className={`inline-block rounded border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${
        sevStyle(severity)
      }`}
    >
      {severity ?? "UNKNOWN"}
    </span>
  );
}

function RiskBadge({ score }: { score?: number }) {
  if (score === undefined || score === null) return <span className="text-zinc-500 text-xs">—</span>;
  const colour =
    score >= 8.5 ? "text-red-400" :
    score >= 6   ? "text-orange-400" :
    score >= 3   ? "text-yellow-400" :
                   "text-zinc-400";
  return <span className={`font-mono font-semibold text-sm ${colour}`}>{score.toFixed(1)}</span>;
}

function InfoPill({ label, value }: { label: string; value?: string | number }) {
  if (!value && value !== 0) return null;
  return (
    <span className="inline-flex items-center gap-1 rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-xs text-zinc-400">
      <span className="text-zinc-500">{label}</span>
      <span className="text-zinc-200">{value}</span>
    </span>
  );
}

// Normalises a finding regardless of whether the backend returned it
// flat (orchestrator path) or nested under a "finding" key (legacy path).
function normalise(f: ReportFinding): ReportFinding {
  if (f.rule_id || f.title || f.severity) return f;
  if (f.finding) {
    return {
      ...f.finding,
      ai_analysis: f.ai_analysis,
      risk_score: f.risk_score,
      cwe: f.cwe,
      owasp: f.owasp,
      mitre: f.mitre,
      framework: f.framework,
      snippet: f.snippet,
    };
  }
  return f;
}

// ─────────────────────────────────────────────────────────────────────
// FindingRow — expandable accordion row
// ─────────────────────────────────────────────────────────────────────

function FindingRow({ raw, index }: { raw: ReportFinding; index: number }) {
  const [open, setOpen] = useState(false);
  const f = normalise(raw);
  const ai = f.ai_analysis;

  const ruleOrTitle = f.title ?? f.rule_id ?? f.finding?.rule_id ?? `Finding #${index + 1}`;
  const pathLine = f.path
    ? `${f.path}${f.line ? `:${f.line}` : ""}`
    : f.finding?.path ?? "—";

  return (
    <>
      {/* Collapsed row */}
      <tr
        className="border-t border-zinc-800 hover:bg-zinc-800/40 cursor-pointer transition-colors"
        onClick={() => setOpen((p) => !p)}
      >
        <td className="px-4 py-3 text-xs text-zinc-500 w-8">{index + 1}</td>
        <td className="px-4 py-3">
          <span className="text-sm font-medium text-zinc-100">{ruleOrTitle}</span>
        </td>
        <td className="px-4 py-3"><SevBadge severity={f.severity} /></td>
        <td className="px-4 py-3"><RiskBadge score={f.risk_score} /></td>
        <td className="px-4 py-3 font-mono text-xs text-zinc-400 max-w-[240px] truncate">{pathLine}</td>
        <td className="px-4 py-3 text-zinc-500 text-sm">
          {open ? "▲" : "▼"}
        </td>
      </tr>

      {/* Expanded accordion — AI detail */}
      {open && (
        <tr className="border-t border-zinc-800 bg-zinc-950">
          <td colSpan={6} className="px-6 py-5">
            <div className="grid gap-5 md:grid-cols-2">

              {/* Left column */}
              <div className="space-y-4">
                {ai?.summary && (
                  <Section title="AI Summary">
                    <p className="text-sm leading-6 text-zinc-300">{ai.summary}</p>
                  </Section>
                )}
                {ai?.attack_scenario && (
                  <Section title="Attack Scenario">
                    <p className="text-sm leading-6 text-zinc-300">{ai.attack_scenario}</p>
                  </Section>
                )}
                {ai?.business_impact && (
                  <Section title="Business Impact">
                    <p className="text-sm leading-6 text-zinc-300">{ai.business_impact}</p>
                  </Section>
                )}
                {ai?.secure_fix && (
                  <Section title="Secure Fix">
                    <p className="text-sm leading-6 text-zinc-300">{ai.secure_fix}</p>
                  </Section>
                )}
                {(ai?.developer_remediation_steps ?? []).length > 0 && (
                  <Section title="Remediation Steps">
                    <ol className="list-decimal list-inside space-y-1 text-sm text-zinc-300">
                      {ai!.developer_remediation_steps!.map((s, i) => (
                        <li key={i}>{s}</li>
                      ))}
                    </ol>
                  </Section>
                )}
              </div>

              {/* Right column */}
              <div className="space-y-4">
                {/* Taxonomy pills */}
                <div className="flex flex-wrap gap-2">
                  <InfoPill label="CWE" value={f.cwe} />
                  <InfoPill label="OWASP" value={f.owasp} />
                  <InfoPill label="MITRE" value={f.mitre} />
                  <InfoPill label="Framework" value={f.framework?.primary_framework} />
                  <InfoPill label="Exploitability" value={ai?.exploitability_score} />
                  <InfoPill label="FP probability" value={ai?.false_positive_probability} />
                </div>

                {/* Vulnerable snippet */}
                {f.snippet?.vulnerable_line && (
                  <Section title="Vulnerable Snippet">
                    <pre className="mt-1 max-h-40 overflow-auto rounded-lg border border-zinc-800 bg-black p-3 text-xs text-zinc-200 font-mono">
                      <code>{f.snippet.vulnerable_line}</code>
                    </pre>
                  </Section>
                )}

                {/* Error from analysis (backend reported an error) */}
                {f.error && (
                  <Section title="Analysis Error">
                    <p className="text-xs text-red-400 font-mono">{f.error}</p>
                  </Section>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs font-semibold uppercase tracking-widest text-zinc-500 mb-1">{title}</p>
      {children}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// ReportView — rendered once we have data
// ─────────────────────────────────────────────────────────────────────

function ReportView({ report }: { report: Report }) {
  const summary = report.summary ?? {};
  // Defensive fallback: backend always sends findings:[] now, but guard
  // here too so an old cached response can never crash the render.
  const findings = report.findings ?? [];

  function downloadJson() {
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `report-${report.scan_id}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <div className="space-y-6">
      {/* ── Report header ── */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <h2 className="text-xl font-semibold text-zinc-100">
              {report.project_name ?? "Security Report"}
            </h2>
            <p className="font-mono text-xs text-zinc-500">{report.scan_id}</p>
            <div className="flex gap-2 pt-1 flex-wrap">
              {report.scan_type && (
                <span className="rounded border border-zinc-700 px-2 py-0.5 text-xs text-zinc-400 uppercase">
                  {report.scan_type}
                </span>
              )}
              <span className="rounded border border-zinc-700 px-2 py-0.5 text-xs text-zinc-400">
                {report.finding_count} finding{report.finding_count !== 1 ? "s" : ""}
              </span>
            </div>
          </div>
          <button
            onClick={downloadJson}
            className="shrink-0 rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2 text-sm text-zinc-200 hover:bg-zinc-700 transition-colors"
          >
            ↓ Export JSON
          </button>
        </div>

        {/* Severity summary */}
        {Object.keys(summary).length > 0 && (
          <div className="mt-5 flex flex-wrap gap-3">
            {["critical", "high", "medium", "low"].map((sev) => {
              const count = summary[sev] ?? summary[sev.toUpperCase()];
              if (!count && count !== 0) return null;
              return (
                <div
                  key={sev}
                  className={`rounded-lg border px-4 py-2 text-center min-w-[72px] ${
                    sevStyle(sev)
                  }`}
                >
                  <p className="text-2xl font-bold tabular-nums">{count}</p>
                  <p className="text-xs uppercase tracking-wide mt-0.5">{sev}</p>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Findings table ── */}
      {findings.length === 0 ? (
        <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-12 text-center">
          <p className="text-zinc-400">No findings in this scan.</p>
        </div>
      ) : (
        <div className="rounded-xl border border-zinc-800 bg-zinc-950 overflow-hidden">
          <div className="px-5 py-3 border-b border-zinc-800">
            <p className="text-sm font-semibold text-zinc-200">Findings</p>
            <p className="text-xs text-zinc-500 mt-0.5">Click any row to expand AI analysis</p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="text-xs text-zinc-500 uppercase tracking-wider">
                  <th className="px-4 py-2 w-8">#</th>
                  <th className="px-4 py-2">Rule / Title</th>
                  <th className="px-4 py-2">Severity</th>
                  <th className="px-4 py-2">Risk</th>
                  <th className="px-4 py-2">Location</th>
                  <th className="px-4 py-2 w-8"></th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f, i) => (
                  <FindingRow key={f.id ?? i} raw={f} index={i} />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────

export default function ReportsPage() {
  const [selectedScanId, setSelectedScanId] = useState("");
  const [manualScanId, setManualScanId] = useState("");
  const [useManual, setUseManual] = useState(false);

  const { data: scans, isLoading: scansLoading } = useScansForPicker();
  const { mutate, data: report, isPending, isError, error, reset } = useGenerateReport();

  const completedScans = (scans ?? []).filter((s) => s.status === "COMPLETED");

  function handleGenerate() {
    const id = useManual ? manualScanId.trim() : selectedScanId;
    if (!id) return;
    reset(); // clear any previous report/error
    mutate(id);
  }

  const activeScanId = useManual ? manualScanId.trim() : selectedScanId;

  return (
    <div className="space-y-6 p-6">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">Reports</h1>
        <p className="text-zinc-400 mt-1 text-sm">
          Generate a full AI-enriched security report for any completed scan.
        </p>
      </div>

      {/* ── Scan selector card ── */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6 space-y-4">
        <p className="text-sm font-semibold text-zinc-200">Select a scan</p>

        {/* Toggle: picker vs manual entry */}
        <div className="flex gap-3 text-sm">
          <button
            onClick={() => { setUseManual(false); reset(); }}
            className={`px-3 py-1.5 rounded-lg border transition-colors ${
              !useManual
                ? "border-zinc-500 bg-zinc-800 text-zinc-100"
                : "border-zinc-700 text-zinc-500 hover:text-zinc-300"
            }`}
          >
            Pick from list
          </button>
          <button
            onClick={() => { setUseManual(true); reset(); }}
            className={`px-3 py-1.5 rounded-lg border transition-colors ${
              useManual
                ? "border-zinc-500 bg-zinc-800 text-zinc-100"
                : "border-zinc-700 text-zinc-500 hover:text-zinc-300"
            }`}
          >
            Enter scan ID manually
          </button>
        </div>

        {/* Dropdown */}
        {!useManual && (
          <div>
            {scansLoading ? (
              <p className="text-xs text-zinc-500">Loading scans…</p>
            ) : completedScans.length === 0 ? (
              <p className="text-xs text-zinc-500">
                No completed scans found. Run a scan first, then return here.
              </p>
            ) : (
              <select
                value={selectedScanId}
                onChange={(e) => { setSelectedScanId(e.target.value); reset(); }}
                className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:ring-1 focus:ring-zinc-500"
              >
                <option value="">-- Select a completed scan --</option>
                {completedScans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.target} — {s.findingsCount} finding{s.findingsCount !== 1 ? "s" : ""} — {s.id.slice(0, 8)}…
                  </option>
                ))}
              </select>
            )}
          </div>
        )}

        {/* Manual ID input */}
        {useManual && (
          <input
            type="text"
            placeholder="Paste scan_id here e.g. 3fa85f64-5717-..."
            value={manualScanId}
            onChange={(e) => { setManualScanId(e.target.value); reset(); }}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm font-mono text-zinc-100 placeholder-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-500"
          />
        )}

        {/* Generate button */}
        <button
          onClick={handleGenerate}
          disabled={!activeScanId || isPending}
          className="rounded-lg bg-zinc-100 px-5 py-2 text-sm font-semibold text-zinc-900 hover:bg-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {isPending ? (
            <span className="flex items-center gap-2">
              <span className="inline-block w-4 h-4 border-2 border-zinc-400 border-t-zinc-900 rounded-full animate-spin" />
              Generating…
            </span>
          ) : (
            "Generate Report"
          )}
        </button>
      </div>

      {/* ── Error state ── */}
      {isError && (
        <div className="rounded-xl border border-red-800 bg-red-950/40 p-5">
          <p className="text-sm font-semibold text-red-300">Report generation failed</p>
          <p className="text-xs text-red-400 mt-1 font-mono">
            {(error as Error)?.message ?? "Unknown error"}
          </p>
          <p className="text-xs text-zinc-500 mt-2">
            Make sure the scan is COMPLETED and the scan_id is correct.
          </p>
        </div>
      )}

      {/* ── Generating skeleton ── */}
      {isPending && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-8">
          <div className="space-y-3 animate-pulse">
            <div className="h-5 w-48 rounded bg-zinc-800" />
            <div className="h-3 w-32 rounded bg-zinc-800" />
            <div className="flex gap-3 mt-4">
              {["critical", "high", "medium", "low"].map((s) => (
                <div key={s} className="h-16 w-16 rounded-lg bg-zinc-800" />
              ))}
            </div>
            <div className="h-48 w-full rounded-lg bg-zinc-800 mt-4" />
          </div>
          <p className="text-xs text-zinc-500 mt-4 text-center">
            Running AI analysis on all findings. This may take 30–90 seconds depending on finding count.
          </p>
        </div>
      )}

      {/* ── Report ── */}
      {report && !isPending && <ReportView report={report} />}
    </div>
  );
}
