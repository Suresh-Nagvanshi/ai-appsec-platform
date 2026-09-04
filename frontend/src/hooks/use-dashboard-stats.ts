/**
 * use-dashboard-stats
 * ====================
 * Single hook that fetches both data sources the dashboard needs:
 *   1. GET /findings          → total, severity breakdown, resolved count
 *   2. GET /api/scans         → recent scans (newest 5) + unique repo count
 *
 * Derives every KPI from real API data so StatsCards and
 * SecurityPostureChart never show hardcoded numbers again.
 */

"use client";

import { useQuery } from "@tanstack/react-query";
import { getFindings, type Finding } from "@/services/findings.service";
import { listScans, type ScanRecord } from "@/services/scans.service";

// ── Derived stats shape ──────────────────────────────────────────────────

export interface DashboardStats {
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  resolvedFindings: number;
  repositoryCount: number;
  recentScans: ScanRecord[];
  recentFindings: Finding[];
  isLoading: boolean;
  isError: boolean;
}

/**
 * Resolve the effective severity from a finding that may be:
 *   (a) a deduplicated group wrapper produced by FindingDeduplicator, or
 *   (b) a flat finding object.
 *
 * Deduplication wrapper shape:
 *   {
 *     representative_finding: {
 *       finding: { extra: { severity }, severity },
 *       risk:    { severity }
 *     },
 *     severity: undefined   ← stamp by FindingsRepository is on the wrapper
 *                              but severity itself is nested
 *   }
 */
function resolveSeverity(f: Finding): string {
  return (
    f.representative_finding?.finding?.extra?.severity ||
    f.representative_finding?.risk?.severity ||
    f.representative_finding?.finding?.severity ||
    f.severity ||
    ""
  ).toUpperCase();
}

// ── Hook ───────────────────────────────────────────────────────────────────

export function useDashboardStats(): DashboardStats {
  // Fetch ALL findings in one call (limit=1000 covers any realistic MVP dataset)
  const findingsQuery = useQuery({
    queryKey: ["findings", "dashboard"],
    queryFn: () => getFindings({ limit: 1000 }),
    staleTime: 60_000,
  });

  // Fetch all scans — reuse the same query key as the scan picker
  const scansQuery = useQuery({
    queryKey: ["scans", "all"],
    queryFn: listScans,
    staleTime: 30_000,
  });

  const isLoading = findingsQuery.isLoading || scansQuery.isLoading;
  const isError   = findingsQuery.isError   || scansQuery.isError;

  // ── Derive KPIs from findings ────────────────────────────────────────
  const allFindings: Finding[] = findingsQuery.data?.findings ?? [];
  const totalFindings  = findingsQuery.data?.total ?? 0;

  const bySeverity = (sev: string) =>
    allFindings.filter((f) => resolveSeverity(f) === sev).length;

  const criticalFindings = bySeverity("CRITICAL");
  const highFindings     = bySeverity("HIGH");
  const mediumFindings   = bySeverity("MEDIUM");
  const lowFindings      = bySeverity("LOW");

  const resolvedFindings = allFindings.filter(
    (f) => f.status === "resolved"
  ).length;

  // 5 most recent findings for the Recent Findings card
  const recentFindings = allFindings.slice(0, 5);

  // ── Derive KPIs from scans ──────────────────────────────────────────
  const allScans: ScanRecord[] = scansQuery.data ?? [];

  // Unique repo count = distinct target values across all scans
  const repositoryCount = new Set(
    allScans.map((s) => s.target)
  ).size;

  // 5 most recent scans for the Recent Scans card (already sorted newest-first by backend)
  const recentScans = allScans.slice(0, 5);

  return {
    totalFindings,
    criticalFindings,
    highFindings,
    mediumFindings,
    lowFindings,
    resolvedFindings,
    repositoryCount,
    recentScans,
    recentFindings,
    isLoading,
    isError,
  };
}
