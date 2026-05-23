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
  QUEUED: "bg-yellow-100 text-yellow-800",
  RUNNING: "bg-blue-100 text-blue-800",
  COMPLETED: "bg-green-100 text-green-800",
  FAILED: "bg-red-100 text-red-800",
};

const STEP_COLOR: Record<string, string> = {
  PENDING: "text-gray-400",
  RUNNING: "text-blue-600 animate-pulse",
  COMPLETED: "text-green-600",
  FAILED: "text-red-600",
};

const LOG_COLOR: Record<string, string> = {
  INFO: "text-gray-300",
  WARNING: "text-yellow-400",
  ERROR: "text-red-400",
};

export default function ScanSessionPage() {
  const { id } = useParams<{ id: string }>();
  const { data: scan, isLoading, error } = useScanPolling(id);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 p-6 text-red-700">
        <p className="font-semibold">Could not load scan</p>
        <p className="text-sm mt-1">{error?.message ?? "Scan not found"}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
            Scan Session
          </h1>
          <p className="text-sm text-gray-500 font-mono mt-1">{scan.id}</p>
        </div>
        <span
          className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${
            STATUS_COLOR[scan.status] ?? "bg-gray-100 text-gray-700"
          }`}
        >
          {scan.status}
        </span>
      </div>

      {/* Meta */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 text-sm">
        <MetaCard label="Type"    value={scan.scanType.toUpperCase()} />
        <MetaCard label="Target"  value={scan.target} mono />
        <MetaCard label="Started" value={new Date(scan.startedAt).toLocaleTimeString()} />
        <MetaCard label="Findings" value={String(scan.findingsCount)} />
      </div>

      {/* Progress bar */}
      <div>
        <div className="flex justify-between text-xs text-gray-500 mb-1">
          <span>Progress</span>
          <span>{scan.progress}%</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2">
          <div
            className="bg-blue-600 h-2 rounded-full transition-all duration-500"
            style={{ width: `${scan.progress}%` }}
          />
        </div>
      </div>

      {/* Timeline */}
      <div>
        <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
          Pipeline Steps
        </h2>
        <ol className="space-y-2">
          {scan.timeline.map((step) => (
            <li key={step.id} className="flex items-center gap-3 text-sm">
              <span className={`text-lg ${STEP_COLOR[step.status] ?? ""}`}>
                {step.status === "COMPLETED"
                  ? "✓"
                  : step.status === "FAILED"
                  ? "✗"
                  : step.status === "RUNNING"
                  ? "●"
                  : "○"}
              </span>
              <span className="text-gray-700 dark:text-gray-300">{step.name}</span>
              <span className="text-xs text-gray-400 ml-auto">{step.status}</span>
            </li>
          ))}
        </ol>
      </div>

      {/* Failure reason */}
      {scan.status === "FAILED" && scan.failureReason && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">
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
        <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
          Logs
        </h2>
        <div className="bg-gray-900 rounded-lg p-4 h-64 overflow-y-auto font-mono text-xs space-y-1">
          {scan.logs.length === 0 && (
            <p className="text-gray-500">No logs yet…</p>
          )}
          {scan.logs.map((log) => (
            <p key={log.id} className={LOG_COLOR[log.level] ?? "text-gray-300"}>
              <span className="text-gray-500">[{log.time}] </span>
              <span className="text-gray-400">[{log.level}] </span>
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
    <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 p-3">
      <p className="text-xs text-gray-500">{label}</p>
      <p
        className={`mt-1 text-sm font-medium text-gray-900 dark:text-gray-100 truncate ${
          mono ? "font-mono" : ""
        }`}
      >
        {value}
      </p>
    </div>
  );
}
