"use client";

import { useParams } from "next/navigation";

import { useScanDetails } from "@/hooks/use-scan-details";
import { useScans } from "@/hooks/use-scans";

export default function ScanDetailsPage() {

  const params = useParams();

  const scanId = params.id as string;

  const {
    data: scanDetails,
    isLoading
  } = useScanDetails(scanId);

  const {
    data: scans
  } = useScans();

  const currentScan = scans?.find(
    scan => scan.id === scanId
  );

  if (isLoading || !scanDetails) {
    return (
      <div className="p-6">
        Loading scan details...
      </div>
    );
  }

  return (

    <div className="space-y-6">

      {/* Header */}

      <div className="rounded-xl border border-zinc-800 p-6">

        <div className="flex justify-between items-center">

          <div>

            <h1 className="text-3xl font-bold">

              Scan Session

            </h1>

            <p className="text-zinc-400 mt-2">

              Scan ID: {scanId}

            </p>

          </div>

          <span
            className={`
            px-4 py-2 rounded-full text-sm
            ${currentScan?.status === "RUNNING"
              ? "bg-blue-500/20 text-blue-400"
              : ""}

            ${currentScan?.status === "COMPLETED"
              ? "bg-green-500/20 text-green-400"
              : ""}

            ${currentScan?.status === "FAILED"
              ? "bg-red-500/20 text-red-400"
              : ""}
          `}
          >
            {currentScan?.status}
          </span>

        </div>

      </div>

      {/* Summary */}

      <div className="grid grid-cols-4 gap-6">

        <div className="rounded-xl border border-zinc-800 p-5">
          <p className="text-zinc-400">Critical</p>
          <h2 className="text-4xl font-bold text-red-400">
            {scanDetails.summary.critical}
          </h2>
        </div>

        <div className="rounded-xl border border-zinc-800 p-5">
          <p className="text-zinc-400">High</p>
          <h2 className="text-4xl font-bold">
            {scanDetails.summary.high}
          </h2>
        </div>

        <div className="rounded-xl border border-zinc-800 p-5">
          <p className="text-zinc-400">Medium</p>
          <h2 className="text-4xl font-bold">
            {scanDetails.summary.medium}
          </h2>
        </div>

        <div className="rounded-xl border border-zinc-800 p-5">
          <p className="text-zinc-400">Low</p>
          <h2 className="text-4xl font-bold">
            {scanDetails.summary.low}
          </h2>
        </div>

      </div>

      {/* Timeline + Logs */}

      <div className="grid grid-cols-2 gap-6">

        <div className="rounded-xl border border-zinc-800 p-6">

          <h2 className="text-xl font-semibold mb-6">
            Scan Timeline
          </h2>

          <div className="space-y-6">

            {scanDetails.timeline.map(step => (

              <div
                key={step.id}
                className="flex items-center gap-4"
              >

                <div
                  className={`
                  h-3 w-3 rounded-full

                  ${step.status === "COMPLETED"
                    ? "bg-green-500"
                    : ""}

                  ${step.status === "RUNNING"
                    ? "bg-blue-500"
                    : ""}

                  ${step.status === "PENDING"
                    ? "bg-zinc-600"
                    : ""}

                  ${step.status === "FAILED"
                    ? "bg-red-500"
                    : ""}
                `}
                />

                <div>

                  <p>{step.title}</p>

                  <p className="text-sm text-zinc-500">
                    {step.status}
                  </p>

                </div>

              </div>

            ))}

          </div>

        </div>

        <div className="rounded-xl border border-zinc-800 p-6">

          <h2 className="text-xl font-semibold mb-6">
            Scan Logs
          </h2>

          <div className="space-y-4">

            {scanDetails.logs.map(log => (

              <div
                key={log.id}
                className="flex gap-4 border-b border-zinc-800 pb-3"
              >

                <span className="text-zinc-500">
                  {log.time}
                </span>

                <span
                  className={`
                  font-semibold

                  ${log.level === "INFO"
                    ? "text-blue-400"
                    : ""}

                  ${log.level === "WARNING"
                    ? "text-yellow-400"
                    : ""}

                  ${log.level === "ERROR"
                    ? "text-red-400"
                    : ""}
                `}
                >
                  {log.level}
                </span>

                <span>
                  {log.message}
                </span>

              </div>

            ))}

          </div>

        </div>

      </div>

    </div>

  );

}