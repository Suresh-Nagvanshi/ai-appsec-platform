"use client";

import { useState, useEffect, useRef } from "react";
import {
  Globe,
  Play,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Shield,
  FileSearch,
  Activity,
  ChevronDown,
  ChevronUp,
  ExternalLink,
} from "lucide-react";
import {
  startWebsiteScan,
  getWebsiteScan,
  listWebsiteScans,
  type WebsiteScan,
  type WebsiteScanFinding,
} from "@/services/website-scans.service";

// ── Severity badge ────────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    CRITICAL: "bg-red-500/20 text-red-400 border border-red-500/30",
    HIGH:     "bg-orange-500/20 text-orange-400 border border-orange-500/30",
    MEDIUM:   "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30",
    LOW:      "bg-blue-500/20 text-blue-400 border border-blue-500/30",
  };
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${map[severity] ?? map.LOW}`}>
      {severity}
    </span>
  );
}

// ── Status icon ───────────────────────────────────────────────────────────────

function StatusIcon({ status }: { status: WebsiteScan["status"] }) {
  if (status === "COMPLETED") return <CheckCircle2 size={16} className="text-green-400" />;
  if (status === "FAILED")    return <AlertTriangle size={16} className="text-red-400" />;
  if (status === "RUNNING")   return <Activity size={16} className="text-yellow-400 animate-pulse" />;
  return <Clock size={16} className="text-zinc-400" />;
}

// ── Finding row ───────────────────────────────────────────────────────────────

function FindingRow({ finding }: { finding: WebsiteScanFinding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/50">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="flex w-full items-center gap-3 p-4 text-left hover:bg-zinc-800/50 transition-colors"
      >
        <SeverityBadge severity={finding.severity} />
        <div className="flex-1 min-w-0">
          <p className="font-medium truncate">{finding.title}</p>
          <p className="text-xs text-zinc-500 truncate">{finding.url}</p>
        </div>
        <span className="shrink-0 text-xs text-zinc-600">{finding.category}</span>
        {expanded ? (
          <ChevronUp size={14} className="shrink-0 text-zinc-500" />
        ) : (
          <ChevronDown size={14} className="shrink-0 text-zinc-500" />
        )}
      </button>

      {expanded && (
        <div className="border-t border-zinc-800 p-4 space-y-3 text-sm">
          <p className="text-zinc-300">{finding.description}</p>
          {finding.evidence && (
            <div className="rounded bg-black/60 p-3 font-mono text-xs text-zinc-400">
              <span className="text-zinc-600 select-none">Evidence: </span>
              {finding.evidence}
            </div>
          )}
          {finding.recommendation && (
            <div className="rounded bg-green-950/30 border border-green-800/30 p-3">
              <p className="text-xs text-green-400 font-semibold mb-1">Recommendation</p>
              <p className="text-zinc-300">{finding.recommendation}</p>
            </div>
          )}
          <a
            href={finding.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            View page <ExternalLink size={10} />
          </a>
        </div>
      )}
    </div>
  );
}

// ── Scan result card ──────────────────────────────────────────────────────────

function ScanCard({ scan, onClick }: { scan: WebsiteScan; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full rounded-xl border border-zinc-800 bg-zinc-950 p-5 text-left space-y-3 hover:border-zinc-700 transition-colors"
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <Globe size={16} className="shrink-0 text-zinc-500" />
          <span className="truncate font-medium text-sm">{scan.target}</span>
        </div>
        <StatusIcon status={scan.status} />
      </div>

      {scan.status === "RUNNING" && (
        <div className="space-y-1">
          <div className="h-1.5 w-full rounded-full bg-zinc-800 overflow-hidden">
            <div
              className="h-full rounded-full bg-red-600 transition-all duration-500"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
          <p className="text-xs text-zinc-500">{scan.progress}%</p>
        </div>
      )}

      <div className="flex gap-4 text-xs text-zinc-500">
        <span>{scan.pagesScanned} pages</span>
        <span>{scan.findingsCount} findings</span>
        {scan.summary?.critical > 0 && (
          <span className="text-red-400">{scan.summary.critical} critical</span>
        )}
      </div>
    </button>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function WebsiteSecurityPage() {
  const [url, setUrl] = useState("");
  const [maxPages, setMaxPages] = useState(20);
  const [maxDepth, setMaxDepth] = useState(3);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scans, setScans] = useState<WebsiteScan[]>([]);
  const [selectedScan, setSelectedScan] = useState<WebsiteScan | null>(null);
  const [loadingScans, setLoadingScans] = useState(true);
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Load existing scans on mount
  useEffect(() => {
    listWebsiteScans()
      .then(setScans)
      .catch(console.error)
      .finally(() => setLoadingScans(false));
  }, []);

  // Poll the selected scan if it's still running
  useEffect(() => {
    if (!selectedScan) return;
    if (selectedScan.status === "COMPLETED" || selectedScan.status === "FAILED") {
      if (pollingRef.current) clearInterval(pollingRef.current);
      return;
    }
    pollingRef.current = setInterval(async () => {
      try {
        const updated = await getWebsiteScan(selectedScan.id);
        setSelectedScan(updated);
        setScans((prev) => prev.map((s) => (s.id === updated.id ? updated : s)));
      } catch {/* ignore */}
    }, 2000);
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [selectedScan?.id, selectedScan?.status]);

  async function handleStartScan() {
    if (!url.trim()) return;
    setError(null);
    setScanning(true);
    try {
      const scanId = await startWebsiteScan(url.trim(), maxPages, maxDepth);
      const newScan = await getWebsiteScan(scanId);
      setScans((prev) => [newScan, ...prev]);
      setSelectedScan(newScan);
      setUrl("");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to start scan";
      setError(msg);
    } finally {
      setScanning(false);
    }
  }

  const filteredFindings = (selectedScan?.findings ?? []).filter(
    (f) => severityFilter === "ALL" || f.severity === severityFilter
  );

  const summaryColors = {
    critical: "text-red-400",
    high:     "text-orange-400",
    medium:   "text-yellow-400",
    low:      "text-blue-400",
  };

  return (
    <div className="space-y-8">

      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <Globe size={28} className="text-red-500" />
          Website Security
        </h1>
        <p className="mt-2 text-zinc-400">
          Crawl and analyse websites for security misconfigurations, header issues, and client-side vulnerabilities.
        </p>
      </div>

      <div className="grid gap-8 lg:grid-cols-3">

        {/* Left panel — scanner form + scan list */}
        <div className="space-y-6">

          {/* Scan form */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6 space-y-4">
            <h2 className="font-semibold flex items-center gap-2">
              <Shield size={16} className="text-red-500" />
              New Website Scan
            </h2>

            <div className="space-y-3">
              <div>
                <label className="mb-1.5 block text-xs text-zinc-400">Target URL</label>
                <input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleStartScan()}
                  placeholder="https://example.com"
                  className="w-full rounded-lg border border-zinc-800 bg-black px-4 py-3 text-sm outline-none focus:border-red-500 transition-colors"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1.5 block text-xs text-zinc-400">Max Pages</label>
                  <select
                    value={maxPages}
                    onChange={(e) => setMaxPages(Number(e.target.value))}
                    className="w-full rounded-lg border border-zinc-800 bg-black px-3 py-2 text-sm"
                  >
                    {[10, 20, 50, 100].map((n) => (
                      <option key={n} value={n}>{n}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="mb-1.5 block text-xs text-zinc-400">Max Depth</label>
                  <select
                    value={maxDepth}
                    onChange={(e) => setMaxDepth(Number(e.target.value))}
                    className="w-full rounded-lg border border-zinc-800 bg-black px-3 py-2 text-sm"
                  >
                    {[1, 2, 3, 4, 5].map((n) => (
                      <option key={n} value={n}>{n}</option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            {error && (
              <p className="rounded-lg bg-red-950/30 border border-red-800/30 px-3 py-2 text-xs text-red-400">
                {error}
              </p>
            )}

            <button
              disabled={scanning || !url.trim()}
              onClick={handleStartScan}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-red-600 px-4 py-3 font-medium text-white disabled:opacity-50 hover:bg-red-700 transition-colors"
            >
              <Play size={16} />
              {scanning ? "Starting..." : "Start Scan"}
            </button>
          </div>

          {/* Scan history */}
          <div>
            <h2 className="mb-3 text-sm font-semibold text-zinc-400 uppercase tracking-wider">
              Scan History
            </h2>
            {loadingScans ? (
              <p className="text-sm text-zinc-500">Loading...</p>
            ) : scans.length === 0 ? (
              <p className="text-sm text-zinc-600">No scans yet. Start one above.</p>
            ) : (
              <div className="space-y-3">
                {scans.slice(0, 10).map((scan) => (
                  <ScanCard
                    key={scan.id}
                    scan={scan}
                    onClick={() => setSelectedScan(scan)}
                  />
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right panel — scan detail */}
        <div className="lg:col-span-2">
          {!selectedScan ? (
            <div className="flex h-64 items-center justify-center rounded-xl border border-dashed border-zinc-800 text-zinc-600">
              <div className="text-center space-y-2">
                <FileSearch size={32} className="mx-auto" />
                <p>Select or start a scan to see results</p>
              </div>
            </div>
          ) : (
            <div className="space-y-6">

              {/* Scan summary */}
              <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <StatusIcon status={selectedScan.status} />
                      <span className="text-sm font-medium capitalize text-zinc-400">
                        {selectedScan.status}
                      </span>
                    </div>
                    <p className="mt-1 text-lg font-semibold truncate">{selectedScan.target}</p>
                  </div>
                  <div className="text-right shrink-0 text-sm text-zinc-500">
                    <p>{selectedScan.pagesScanned} pages scanned</p>
                    <p>{selectedScan.findingsCount} findings</p>
                  </div>
                </div>

                {/* Progress bar for running scan */}
                {selectedScan.status === "RUNNING" && (
                  <div className="mt-4 space-y-1">
                    <div className="h-2 w-full rounded-full bg-zinc-800 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-red-600 transition-all duration-700"
                        style={{ width: `${selectedScan.progress}%` }}
                      />
                    </div>
                    <div className="flex justify-between text-xs text-zinc-600">
                      <span>{selectedScan.logs?.slice(-1)[0]?.message ?? "Scanning..."}</span>
                      <span>{selectedScan.progress}%</span>
                    </div>
                  </div>
                )}

                {/* Summary counts */}
                {selectedScan.status === "COMPLETED" && (
                  <div className="mt-4 flex gap-6">
                    {(["critical", "high", "medium", "low"] as const).map((sev) => (
                      <div key={sev} className="text-center">
                        <p className={`text-2xl font-bold ${summaryColors[sev]}`}>
                          {selectedScan.summary?.[sev] ?? 0}
                        </p>
                        <p className="text-xs text-zinc-500 capitalize">{sev}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Findings list */}
              {selectedScan.status === "COMPLETED" && selectedScan.findings.length > 0 && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="font-semibold">
                      Findings ({filteredFindings.length})
                    </h3>
                    <div className="flex gap-2">
                      {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => (
                        <button
                          key={sev}
                          onClick={() => setSeverityFilter(sev)}
                          className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                            severityFilter === sev
                              ? "bg-red-600 text-white"
                              : "bg-zinc-800 text-zinc-400 hover:bg-zinc-700"
                          }`}
                        >
                          {sev}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-2">
                    {filteredFindings.map((finding) => (
                      <FindingRow key={finding.id} finding={finding} />
                    ))}
                  </div>
                </div>
              )}

              {/* Timeline */}
              {selectedScan.timeline && (
                <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-5 space-y-3">
                  <h3 className="text-sm font-semibold text-zinc-400">Pipeline</h3>
                  <div className="space-y-2">
                    {selectedScan.timeline.map((step) => (
                      <div key={step.id} className="flex items-center gap-3">
                        <div className={`h-2 w-2 rounded-full shrink-0 ${
                          step.status === "COMPLETED" ? "bg-green-500" :
                          step.status === "RUNNING"   ? "bg-yellow-500 animate-pulse" :
                          "bg-zinc-700"
                        }`} />
                        <span className={`text-sm ${
                          step.status === "COMPLETED" ? "text-zinc-300" :
                          step.status === "RUNNING"   ? "text-yellow-400" :
                          "text-zinc-600"
                        }`}>
                          {step.name}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            </div>
          )}
        </div>

      </div>
    </div>
  );
}
