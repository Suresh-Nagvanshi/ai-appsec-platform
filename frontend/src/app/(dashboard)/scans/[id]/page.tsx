/**
 * Scan Session Page  /scans/[id]
 * ================================
 * Replaces the previous placeholder with a live-data page.
 * Polls the backend every 2 s while the scan is running.
 */

"use client";

import { useParams } from "next/navigation";
import { useScanPolling } from "@/hooks/useScanPolling";

const STATUS_COLOR: Record<string, string> = {
  QUEUED: "border-slate-700 bg-slate-800 text-slate-300",
  RUNNING: "border-amber-400/30 bg-amber-400/10 text-amber-200",
  COMPLETED: "border-emerald-400/30 bg-emerald-400/10 text-emerald-300",
  FAILED: "border-red-400/30 bg-red-400/10 text-red-300",
};

const STEP_COLOR: Record<string, string> = {
  PENDING: "text-slate-600",
  RUNNING: "animate-pulse text-amber-300",
  COMPLETED: "text-emerald-300",
  FAILED: "text-red-300",
};

const LOG_COLOR: Record<string, string> = {
  INFO: "text-slate-300",
  WARNING: "text-amber-300",
  ERROR: "text-red-300",
};

export default function ScanSessionPage() {
  const { id } = useParams<{ id: string }>();
  const { data: scan, isLoading, error } = useScanPolling(id);

  if (isLoading) {
    return (
      <div className="flex min-h-[420px] items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-slate-700 border-t-amber-300" />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="rounded-2xl border border-red-400/20 bg-red-400/[0.06] p-6 text-red-200">
        <p className="font-semibold">Could not load scan</p>
        <p className="text-sm mt-1">{error?.message ?? "Scan not found"}</p>
      </div>
    );
  }

  return (
    <div className="mx-auto w-full max-w-[1300px] space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-amber-300">Live analysis session</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight text-slate-100">{scan.target}</h1>
          <p className="mt-1 font-mono text-xs text-slate-500">{scan.id}</p>
        </div>
        <span
          className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium ${
            STATUS_COLOR[scan.status] ?? "bg-gray-100 text-gray-700"
          }`}
        >
          {scan.status}
        </span>
      </div>

      {/* Meta */}
      <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <MetaCard label="Type"    value={scan.scanType.toUpperCase()} />
        <MetaCard label="Target"  value={scan.target} mono />
        <MetaCard label="Started" value={new Date(scan.startedAt).toLocaleTimeString()} />
        <MetaCard label="Findings" value={String(scan.findingsCount)} />
      </div>

      {/* Progress bar */}
      <div>
        <div className="mb-2 flex justify-between text-xs text-slate-500">
          <span>Progress</span>
          <span>{scan.progress}%</span>
        </div>
        <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
          <div
            className="h-2 rounded-full bg-amber-300 transition-all duration-500"
            style={{ width: `${scan.progress}%` }}
          />
        </div>
      </div>

      {/* Timeline */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-200">
          Pipeline Steps
        </h2>
        <ol className="space-y-2">
          {scan.timeline.map((step) => (
            <li key={step.id} className="flex items-center gap-3 rounded-xl border border-slate-800/80 bg-slate-900/50 px-4 py-3 text-sm">
              <span className={`text-lg ${STEP_COLOR[step.status] ?? ""}`}>
                {step.status === "COMPLETED"
                  ? "✓"
                  : step.status === "FAILED"
                  ? "✗"
                  : step.status === "RUNNING"
                  ? "●"
                  : "○"}
              </span>
              <span className="text-slate-300">{step.name}</span>
              <span className="ml-auto text-xs text-slate-600">{step.status}</span>
            </li>
          ))}
        </ol>
      </div>

      {/* Failure reason */}
      {scan.status === "FAILED" && scan.failureReason && (
        <div className="rounded-xl border border-red-400/20 bg-red-400/[0.06] p-4 text-sm text-red-200">
          <span className="font-semibold">Failure reason: </span>
          {scan.failureReason}
        </div>
      )}

      {/* Summary (completed) */}
      {scan.status === "COMPLETED" && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {Object.entries(scan.summary).map(([sev, count]) => (
            <MetaCard key={sev} label={sev.toUpperCase()} value={String(count)} />
          ))}
        </div>
      )}

      {/* Live logs */}
      <div>
        <h2 className="mb-2 text-sm font-semibold text-slate-200">
          Logs
        </h2>
        <div className="h-64 space-y-1 overflow-y-auto rounded-xl border border-slate-800 bg-[#090d12] p-4 font-mono text-xs">
          {scan.logs.length === 0 && (
            <p className="text-slate-600">No logs yet...</p>
          )}
          {scan.logs.map((log) => (
            <p key={log.id} className={LOG_COLOR[log.level] ?? "text-gray-300"}>
              <span className="text-slate-600">[{log.time}] </span>
              <span className="text-slate-500">[{log.level}] </span>
              {log.message}
            </p>
          ))}
        </div>
      </div>
    </div>
  );
}

function MetaCard({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-[#111820]/90 p-4">
      <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-600">{label}</p>
      <p
        className={`mt-2 truncate text-sm font-medium text-slate-100 ${
          mono ? "font-mono" : ""
        }`}
      >
        {value}
      </p>
    </div>
  );
}
