/**
 * RecentFindings  +  RecentScans
 * ================================
 * RecentFindings — last 5 findings from GET /findings (real data).
 * RecentScans    — last 5 scans from GET /api/scans (real data).
 *
 * Both exported so dashboard/page.tsx can lay them out independently.
 * Previously hardcoded — now driven by useDashboardStats().
 */

"use client";

import Link from "next/link";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { useDashboardStats } from "@/hooks/use-dashboard-stats";
import type { Finding } from "@/services/findings.service";
import type { ScanRecord } from "@/services/scans.service";

// ── Helpers ──────────────────────────────────────────────────────────────

const STATUS_STYLES: Record<string, string> = {
  QUEUED:    "text-yellow-400",
  RUNNING:   "text-blue-400",
  COMPLETED: "text-green-400",
  FAILED:    "text-red-400",
};

function ListSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-3 animate-pulse">
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-900/40 p-4"
        >
          <div className="space-y-2">
            <div className="h-3 w-48 rounded bg-zinc-800" />
            <div className="h-3 w-32 rounded bg-zinc-800" />
          </div>
          <div className="h-5 w-16 rounded bg-zinc-800" />
        </div>
      ))}
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900/20 py-10">
      <p className="text-sm text-zinc-500">{message}</p>
    </div>
  );
}

// Helper: extract a display title from a finding regardless of schema depth
function findingTitle(f: Finding): string {
  const rep = f.representative_finding as Record<string, unknown> | undefined;
  const raw = rep?.finding as Record<string, unknown> | undefined;
  return (
    (f.title as string | undefined) ??
    (raw?.message as string | undefined) ??
    (raw?.rule_id as string | undefined) ??
    (f.rule_id as string | undefined) ??
    "Unknown finding"
  );
}

function findingPath(f: Finding): string {
  const rep = f.representative_finding as Record<string, unknown> | undefined;
  const raw = rep?.finding as Record<string, unknown> | undefined;
  return (
    (f.path as string | undefined) ??
    (raw?.path as string | undefined) ??
    "—"
  );
}

// ── RecentFindings ──────────────────────────────────────────────────────

export function RecentFindings() {
  const { recentFindings, isLoading } = useDashboardStats();

  return (
  <div className="rounded-2xl border border-slate-800 bg-[#111820]/90 p-5 shadow-xl shadow-black/10">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-amber-300">Needs attention</p><h2 className="mt-1 text-lg font-semibold text-slate-100">Recent findings</h2>
          <p className="text-sm text-slate-500">Latest detected vulnerabilities</p>
        </div>
        <Link
          href="/findings"
          className="text-xs text-amber-200 transition-colors hover:text-amber-100"
        >
          View all →
        </Link>
      </div>

      {isLoading ? (
        <ListSkeleton rows={4} />
      ) : recentFindings.length === 0 ? (
        <EmptyState message="No findings yet. Run a scan to see results." />
      ) : (
        <div className="space-y-3">
          {recentFindings.map((f) => (
            <Link
              key={f.id}
              href={`/findings/${f.id}`}
              className="flex items-center justify-between rounded-xl border border-slate-800/80 bg-slate-900/50 p-3.5 transition-colors hover:border-slate-700 hover:bg-slate-800/70"
            >
              <div>
                <h3 className="text-sm font-medium text-slate-100">
                  {findingTitle(f)}
                </h3>
                <p className="mt-1 font-mono text-xs text-slate-500">
                  {findingPath(f)}
                </p>
              </div>
              <SeverityBadge severity={(f.severity as string | undefined) ?? ""} />
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

// ── RecentScans ───────────────────────────────────────────────────────────

export function RecentScans() {
  const { recentScans, isLoading } = useDashboardStats();

  return (
    <div className="rounded-2xl border border-slate-800 bg-[#111820]/90 p-5 shadow-xl shadow-black/10">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-sky-300">Activity stream</p><h2 className="mt-1 text-lg font-semibold text-slate-100">Recent scans</h2>
          <p className="text-sm text-slate-500">Latest scan sessions</p>
        </div>
        <Link
          href="/scans"
          className="text-xs text-sky-200 transition-colors hover:text-sky-100"
        >
          View all →
        </Link>
      </div>

      {isLoading ? (
        <ListSkeleton rows={4} />
      ) : recentScans.length === 0 ? (
        <EmptyState message="No scans yet. Start a scan to see results." />
      ) : (
        <div className="space-y-3">
          {recentScans.map((s: ScanRecord) => (
            <Link
              key={s.id}
              href={`/scans/${s.id}`}
              className="flex items-center justify-between rounded-xl border border-slate-800/80 bg-slate-900/50 p-3.5 transition-colors hover:border-slate-700 hover:bg-slate-800/70"
            >
              <div className="min-w-0">
                <p className="truncate text-sm font-medium text-zinc-100">
                  {s.target}
                </p>
                <p className="mt-1 text-xs text-zinc-400">
                  {s.findingsCount} finding{s.findingsCount !== 1 ? "s" : ""}
                  {s.duration ? ` · ${s.duration}` : ""}
                </p>
              </div>
              <div className="flex flex-col items-end gap-1 shrink-0">
                <span
                  className={`text-xs font-medium ${
                    STATUS_STYLES[s.status] ?? "text-zinc-400"
                  }`}
                >
                  {s.status}
                </span>
                <span className="text-xs text-zinc-500 tabular-nums">
                  {s.criticalCount > 0 ? (
                    <span className="text-red-400">{s.criticalCount} critical</span>
                  ) : (
                    s.scanType.toUpperCase()
                  )}
                </span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
