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
  return (
    (f.title as string | undefined) ??
    (rep?.rule_id as string | undefined) ??
    (f.rule_id as string | undefined) ??
    "Unknown finding"
  );
}

function findingPath(f: Finding): string {
  const rep = f.representative_finding as Record<string, unknown> | undefined;
  return (
    (f.path as string | undefined) ??
    (rep?.path as string | undefined) ??
    "—"
  );
}

// ── RecentFindings ──────────────────────────────────────────────────────

export function RecentFindings() {
  const { recentFindings, isLoading } = useDashboardStats();

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Recent Findings</h2>
          <p className="text-sm text-zinc-400">Latest detected vulnerabilities</p>
        </div>
        <Link
          href="/findings"
          className="text-xs text-zinc-400 hover:text-zinc-200 transition-colors"
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
              className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-900/40 p-4 hover:bg-zinc-800/60 transition-colors"
            >
              <div>
                <h3 className="font-medium text-zinc-100 text-sm">
                  {findingTitle(f)}
                </h3>
                <p className="mt-1 text-xs text-zinc-400 font-mono">
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
    <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Recent Scans</h2>
          <p className="text-sm text-zinc-400">Latest scan sessions</p>
        </div>
        <Link
          href="/scans"
          className="text-xs text-zinc-400 hover:text-zinc-200 transition-colors"
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
              className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-900/40 p-4 hover:bg-zinc-800/60 transition-colors"
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
