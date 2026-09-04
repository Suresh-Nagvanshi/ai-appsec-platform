"use client";

import { useEffect, useRef, useState } from "react";
import {
  Activity, AlertTriangle, ArrowUpRight, CheckCircle2, ChevronDown, ChevronUp,
  Clock, ExternalLink, FileSearch, Globe, Info, Loader2, Play, RefreshCw,
  Shield, XCircle,
} from "lucide-react";
import {
  getWebsiteScan, listWebsiteScans, startWebsiteScan,
  type WebsiteScan, type WebsiteScanFinding,
} from "@/services/website-scans.service";

const severityStyles: Record<string, string> = {
  CRITICAL: "border-red-500/30 bg-red-500/10 text-red-300",
  HIGH: "border-orange-500/30 bg-orange-500/10 text-orange-300",
  MEDIUM: "border-yellow-500/30 bg-yellow-500/10 text-yellow-300",
  LOW: "border-blue-500/30 bg-blue-500/10 text-blue-300",
};
const severityColors = { critical: "text-red-300", high: "text-orange-300", medium: "text-yellow-300", low: "text-blue-300" };

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${severityStyles[severity] ?? severityStyles.LOW}`}>{severity}</span>;
}

function StatusIcon({ status, size = 16 }: { status: WebsiteScan["status"]; size?: number }) {
  if (status === "COMPLETED") return <CheckCircle2 size={size} className="text-emerald-400" />;
  if (status === "FAILED") return <XCircle size={size} className="text-red-400" />;
  if (status === "RUNNING") return <Activity size={size} className="animate-pulse text-amber-300" />;
  return <Clock size={size} className="text-zinc-500" />;
}

function StatusBadge({ status }: { status: WebsiteScan["status"] }) {
  const styles = { COMPLETED: "border-emerald-500/25 bg-emerald-500/10 text-emerald-300", FAILED: "border-red-500/25 bg-red-500/10 text-red-300", RUNNING: "border-amber-500/25 bg-amber-500/10 text-amber-300", QUEUED: "border-zinc-700 bg-zinc-800/70 text-zinc-400" };
  return <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-1 text-[10px] font-semibold uppercase tracking-wide ${styles[status]}`}><StatusIcon status={status} size={12} />{status.toLowerCase()}</span>;
}

function FindingRow({ finding }: { finding: WebsiteScanFinding }) {
  const [expanded, setExpanded] = useState(false);
  return <div className="overflow-hidden rounded-lg border border-zinc-800 bg-zinc-950/70 transition-colors hover:border-zinc-700">
    <button type="button" aria-expanded={expanded} onClick={() => setExpanded((value) => !value)} className="flex w-full items-center gap-3 p-3.5 text-left transition-colors hover:bg-zinc-900/70 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500/70">
      <SeverityBadge severity={finding.severity} />
      <div className="min-w-0 flex-1"><p className="truncate text-sm font-medium text-zinc-100">{finding.title}</p><p className="mt-0.5 truncate text-xs text-zinc-500">{finding.url}</p></div>
      <span className="hidden shrink-0 text-[11px] text-zinc-600 sm:block">{finding.category}</span>
      {expanded ? <ChevronUp size={15} className="shrink-0 text-zinc-500" /> : <ChevronDown size={15} className="shrink-0 text-zinc-500" />}
    </button>
    {expanded && <div className="space-y-3 border-t border-zinc-800 px-3.5 pb-4 pt-3 text-sm">
      <p className="leading-6 text-zinc-300">{finding.description}</p>
      {finding.evidence && <div className="rounded-md border border-zinc-800 bg-black/60 p-3 font-mono text-xs leading-5 text-zinc-400"><span className="select-none text-zinc-600">Evidence: </span>{finding.evidence}</div>}
      {finding.recommendation && <div className="rounded-md border border-emerald-800/30 bg-emerald-950/20 p-3"><p className="mb-1 text-xs font-semibold uppercase tracking-wide text-emerald-400">Recommendation</p><p className="leading-5 text-zinc-300">{finding.recommendation}</p></div>}
      <a href={finding.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-zinc-500 transition-colors hover:text-zinc-200">View page <ExternalLink size={11} /></a>
    </div>}
  </div>;
}

function ScanCard({ scan, selected, onClick }: { scan: WebsiteScan; selected: boolean; onClick: () => void }) {
  return <button type="button" aria-pressed={selected} onClick={onClick} className={`w-full rounded-lg border p-3.5 text-left transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500/70 ${selected ? "border-red-500/50 bg-red-500/[0.06]" : "border-zinc-800 bg-zinc-950 hover:border-zinc-700 hover:bg-zinc-900/70"}`}>
    <div className="flex items-start gap-3"><div className={`mt-0.5 rounded-md p-1.5 ${selected ? "bg-red-500/15 text-red-300" : "bg-zinc-900 text-zinc-500"}`}><Globe size={14} /></div><div className="min-w-0 flex-1"><div className="flex items-start justify-between gap-2"><p className="truncate text-sm font-medium text-zinc-200">{scan.target}</p><StatusIcon status={scan.status} size={15} /></div><p className="mt-1 text-[11px] text-zinc-600">{scan.pagesScanned} pages · {scan.findingsCount} findings</p></div></div>
    {scan.status === "RUNNING" && <div className="mt-3 flex items-center gap-2"><div className="h-1 flex-1 overflow-hidden rounded-full bg-zinc-800"><div className="h-full rounded-full bg-red-500 transition-all duration-500" style={{ width: `${scan.progress}%` }} /></div><span className="text-[10px] tabular-nums text-zinc-500">{scan.progress}%</span></div>}
  </button>;
}

function Metric({ label, value, tone }: { label: string; value: number; tone: keyof typeof severityColors }) {
  return <div className="min-w-0 flex-1 border-l border-zinc-800 pl-4 first:border-l-0 first:pl-0"><p className={`text-2xl font-semibold tabular-nums ${severityColors[tone]}`}>{value}</p><p className="mt-1 text-[10px] font-medium uppercase tracking-wider text-zinc-600">{label}</p></div>;
}

export default function WebsiteSecurityPage() {
  const [url, setUrl] = useState("");
  const [maxPages, setMaxPages] = useState(20);
  const [maxDepth, setMaxDepth] = useState(3);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [scans, setScans] = useState<WebsiteScan[]>([]);
  const [selectedScan, setSelectedScan] = useState<WebsiteScan | null>(null);
  const [loadingScans, setLoadingScans] = useState(true);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => { listWebsiteScans().then(setScans).catch(() => setHistoryError("Unable to load scan history.")).finally(() => setLoadingScans(false)); }, []);
  useEffect(() => {
    if (!selectedScan || ["COMPLETED", "FAILED"].includes(selectedScan.status)) { if (pollingRef.current) clearInterval(pollingRef.current); return; }
    pollingRef.current = setInterval(async () => { try { const updated = await getWebsiteScan(selectedScan.id); setSelectedScan(updated); setScans((previous) => previous.map((scan) => scan.id === updated.id ? updated : scan)); } catch { /* Keep the last known scan state while polling. */ } }, 2000);
    return () => { if (pollingRef.current) clearInterval(pollingRef.current); };
  }, [selectedScan]);

  async function handleStartScan() {
    const target = url.trim();
    if (!target) return;
    setError(null); setScanning(true);
    try { const scanId = await startWebsiteScan(target, maxPages, maxDepth); const newScan = await getWebsiteScan(scanId); setScans((previous) => [newScan, ...previous]); setSelectedScan(newScan); setSeverityFilter("ALL"); setUrl(""); }
    catch (err: unknown) { setError(err instanceof Error ? err.message : "Failed to start scan"); }
    finally { setScanning(false); }
  }

  const filteredFindings = (selectedScan?.findings ?? []).filter((finding) => severityFilter === "ALL" || finding.severity === severityFilter);
  const findingTotal = selectedScan?.findingsCount ?? 0;

  return <div className="mx-auto w-full max-w-[1500px] space-y-6 pb-8">
    <header className="flex flex-col justify-between gap-4 border-b border-zinc-800/80 pb-5 sm:flex-row sm:items-end"><div><div className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-[0.18em] text-red-400"><span className="h-1.5 w-1.5 rounded-full bg-red-500" />Website Security</div><h1 className="text-2xl font-semibold tracking-tight text-zinc-100 sm:text-3xl">External attack surface</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-zinc-500">Crawl public websites and surface security headers, exposed assets, and client-side vulnerabilities.</p></div><div className="flex items-center gap-2 text-xs text-zinc-600"><Shield size={14} />Authorized targets only</div></header>
    <div className="grid items-start gap-5 xl:grid-cols-[340px_minmax(0,1fr)]">
      <aside className="space-y-5">
        <section className="rounded-xl border border-zinc-800 bg-zinc-950 p-4 shadow-2xl shadow-black/10 sm:p-5"><div className="mb-4 flex items-start gap-3"><div className="rounded-lg bg-red-500/10 p-2 text-red-400"><Globe size={17} /></div><div><h2 className="text-sm font-semibold text-zinc-100">New website scan</h2><p className="mt-1 text-xs text-zinc-600">Configure a safe crawl boundary.</p></div></div><div className="space-y-3.5"><div><label htmlFor="target-url" className="mb-1.5 block text-xs font-medium text-zinc-400">Target URL</label><input id="target-url" value={url} onChange={(event) => setUrl(event.target.value)} onKeyDown={(event) => event.key === "Enter" && handleStartScan()} placeholder="https://example.com" className="h-10 w-full rounded-lg border border-zinc-800 bg-black px-3 text-sm text-zinc-100 outline-none transition-colors placeholder:text-zinc-700 focus:border-red-500/70 focus:ring-2 focus:ring-red-500/10" /></div><div className="grid grid-cols-2 gap-3"><div><label htmlFor="max-pages" className="mb-1.5 block text-xs font-medium text-zinc-400">Max pages</label><select id="max-pages" value={maxPages} onChange={(event) => setMaxPages(Number(event.target.value))} className="h-9 w-full rounded-lg border border-zinc-800 bg-black px-2.5 text-sm text-zinc-200 outline-none focus:border-red-500/70">{[10, 20, 50, 100].map((value) => <option key={value} value={value}>{value}</option>)}</select></div><div><label htmlFor="max-depth" className="mb-1.5 block text-xs font-medium text-zinc-400">Max depth</label><select id="max-depth" value={maxDepth} onChange={(event) => setMaxDepth(Number(event.target.value))} className="h-9 w-full rounded-lg border border-zinc-800 bg-black px-2.5 text-sm text-zinc-200 outline-none focus:border-red-500/70">{[1, 2, 3, 4, 5].map((value) => <option key={value} value={value}>{value}</option>)}</select></div></div></div><div className="mt-3 flex items-start gap-2 text-[11px] leading-4 text-zinc-600"><Info size={13} className="mt-0.5 shrink-0" />The scanner stays within the target domain and respects the configured limits.</div>{error && <p role="alert" className="mt-3 rounded-lg border border-red-800/40 bg-red-950/25 px-3 py-2 text-xs leading-5 text-red-300">{error}</p>}<button type="button" disabled={scanning || !url.trim()} onClick={handleStartScan} className="mt-4 flex h-10 w-full items-center justify-center gap-2 rounded-lg bg-red-600 px-4 text-sm font-semibold text-white transition-colors hover:bg-red-500 disabled:pointer-events-none disabled:opacity-50">{scanning ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}{scanning ? "Starting scan" : "Start scan"}<ArrowUpRight size={14} className="ml-auto opacity-60" /></button></section>
        <section><div className="mb-2.5 flex items-center justify-between"><h2 className="text-xs font-semibold uppercase tracking-[0.14em] text-zinc-500">Scan history</h2><span className="text-[10px] tabular-nums text-zinc-700">{scans.length} total</span></div>{loadingScans ? <div className="space-y-2"><div className="h-16 animate-pulse rounded-lg bg-zinc-900" /><div className="h-16 animate-pulse rounded-lg bg-zinc-900" /></div> : historyError ? <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-xs text-zinc-500"><p>{historyError}</p><button type="button" onClick={() => window.location.reload()} className="mt-2 inline-flex items-center gap-1 text-red-400 hover:text-red-300"><RefreshCw size={12} />Retry</button></div> : scans.length === 0 ? <div className="rounded-lg border border-dashed border-zinc-800 px-4 py-7 text-center"><FileSearch size={20} className="mx-auto text-zinc-700" /><p className="mt-2 text-xs text-zinc-600">No scans yet</p></div> : <div className="space-y-2">{scans.slice(0, 10).map((scan) => <ScanCard key={scan.id} scan={scan} selected={selectedScan?.id === scan.id} onClick={() => setSelectedScan(scan)} />)}</div>}</section>
      </aside>
      <main className="min-w-0">{!selectedScan ? <div className="flex min-h-[420px] items-center justify-center rounded-xl border border-dashed border-zinc-800 bg-zinc-950/30 px-6"><div className="max-w-xs text-center"><div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-zinc-900 text-zinc-600"><FileSearch size={23} /></div><h2 className="mt-4 text-sm font-medium text-zinc-400">Select a scan to inspect results</h2><p className="mt-1 text-xs leading-5 text-zinc-600">Your crawl progress, pipeline, and findings will appear here.</p></div></div> : <div className="space-y-5">
        <section className="rounded-xl border border-zinc-800 bg-zinc-950 p-4 sm:p-5"><div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between"><div className="min-w-0"><div className="mb-2 flex items-center gap-2"><StatusBadge status={selectedScan.status} />{selectedScan.duration && <span className="text-[11px] text-zinc-600">{selectedScan.duration}</span>}</div><h2 className="truncate text-lg font-semibold text-zinc-100 sm:text-xl">{selectedScan.target}</h2><p className="mt-1 text-xs text-zinc-600">{selectedScan.pagesScanned} pages scanned · {findingTotal} findings</p></div><div className="grid grid-cols-4 gap-4 sm:w-[280px]"><Metric label="Critical" value={selectedScan.summary?.critical ?? 0} tone="critical" /><Metric label="High" value={selectedScan.summary?.high ?? 0} tone="high" /><Metric label="Medium" value={selectedScan.summary?.medium ?? 0} tone="medium" /><Metric label="Low" value={selectedScan.summary?.low ?? 0} tone="low" /></div></div>{selectedScan.status === "RUNNING" && <div className="mt-5 border-t border-zinc-800 pt-4"><div className="mb-2 flex justify-between gap-4 text-xs"><span className="truncate text-zinc-500">{selectedScan.logs?.slice(-1)[0]?.message ?? "Scanning target..."}</span><span className="shrink-0 tabular-nums text-zinc-400">{selectedScan.progress}%</span></div><div className="h-2 overflow-hidden rounded-full bg-zinc-800"><div className="h-full rounded-full bg-red-500 transition-all duration-700" style={{ width: `${selectedScan.progress}%` }} /></div></div>}{selectedScan.status === "FAILED" && <div className="mt-4 flex items-start gap-2 rounded-lg border border-red-800/40 bg-red-950/20 p-3 text-xs leading-5 text-red-300"><AlertTriangle size={14} className="mt-0.5 shrink-0" />{selectedScan.failureReason ?? "The scan could not be completed."}</div>}</section>
        {selectedScan.status === "COMPLETED" && <section className="space-y-3"><div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between"><div><h3 className="text-sm font-semibold text-zinc-100">Findings</h3><p className="mt-0.5 text-xs text-zinc-600">Review detected issues and recommended fixes.</p></div><div className="flex flex-wrap gap-1 rounded-lg bg-zinc-900 p-1">{["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((severity) => <button type="button" key={severity} onClick={() => setSeverityFilter(severity)} className={`rounded-md px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-wide transition-colors ${severityFilter === severity ? "bg-zinc-700 text-zinc-100" : "text-zinc-500 hover:text-zinc-300"}`}>{severity === "ALL" ? `All ${findingTotal}` : `${severity} ${selectedScan.summary?.[severity.toLowerCase()] ?? 0}`}</button>)}</div></div>{filteredFindings.length > 0 ? <div className="space-y-2">{filteredFindings.map((finding) => <FindingRow key={finding.id} finding={finding} />)}</div> : <div className="rounded-lg border border-dashed border-zinc-800 px-4 py-8 text-center text-xs text-zinc-600">No {severityFilter === "ALL" ? "findings" : `${severityFilter.toLowerCase()} findings`} in this scan.</div>}</section>}
        {selectedScan.timeline?.length > 0 && <section className="rounded-xl border border-zinc-800 bg-zinc-950 p-4 sm:p-5"><div className="mb-4 flex items-center justify-between"><div><h3 className="text-sm font-semibold text-zinc-100">Scan pipeline</h3><p className="mt-0.5 text-xs text-zinc-600">Live progress through each analysis stage.</p></div><Activity size={15} className="text-zinc-600" /></div><div className="grid gap-2 sm:grid-cols-2">{selectedScan.timeline.map((step) => <div key={step.id} className="flex items-center gap-3 rounded-lg border border-zinc-800/80 bg-zinc-900/40 px-3 py-2.5"><div className={`h-2 w-2 shrink-0 rounded-full ${step.status === "COMPLETED" ? "bg-emerald-400" : step.status === "RUNNING" ? "animate-pulse bg-amber-300" : "bg-zinc-700"}`} /><span className={`text-xs ${step.status === "COMPLETED" ? "text-zinc-300" : step.status === "RUNNING" ? "text-amber-300" : "text-zinc-600"}`}>{step.name}</span><span className="ml-auto text-[10px] uppercase tracking-wide text-zinc-700">{step.status.toLowerCase()}</span></div>)}</div></section>}
      </div>}</main>
    </div>
  </div>;
}
