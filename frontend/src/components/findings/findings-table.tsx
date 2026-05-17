"use client";

import { useFindings } from "@/hooks/use-findings";

import { SeverityBadge } from "./severity-badge";

function statusStyles(status: string) {
    switch (status) {
        case "OPEN":
            return "bg-red-500/15 text-red-400";

        case "IN_PROGRESS":
            return "bg-yellow-500/15 text-yellow-400";

        case "RESOLVED":
            return "bg-green-500/15 text-green-400";

        default:
            return "bg-zinc-500/15 text-zinc-400";

    }
}

export function FindingsTable() {

    const {
        data,
        isLoading,
        error,
    } = useFindings();

    if (isLoading) {
        return (<div className="text-zinc-400">
            Loading findings... </div>
        );
    }

    if (error) {
        return (<div className="text-red-400">
            Failed to load findings. </div>
        );
    }

    const findings = data || [];

    return (<div
        className="
     overflow-hidden rounded-xl
     border border-zinc-800
     bg-zinc-950
   "
    > <div className="border-b border-zinc-800 p-6"> <h2 className="text-lg font-semibold">
        Findings </h2>

            ```
            <p className="mt-1 text-sm text-zinc-400">
                Security vulnerabilities detected across repositories.
            </p>
        </div>

        <div className="overflow-x-auto">
            <table className="w-full">

                <thead
                    className="
          border-b border-zinc-800
          bg-zinc-900/40
        "
                >
                    <tr className="text-left text-sm text-zinc-400">

                        <th className="px-6 py-4 font-medium">
                            Finding
                        </th>

                        <th className="px-6 py-4 font-medium">
                            Severity
                        </th>

                        <th className="px-6 py-4 font-medium">
                            Risk Score
                        </th>

                        <th className="px-6 py-4 font-medium">
                            Exploitability
                        </th>

                        <th className="px-6 py-4 font-medium">
                            Status
                        </th>

                    </tr>
                </thead>

                <tbody>

                    {findings.map((finding: any) => (

                        <tr
                            key={finding.id}
                            className="
              border-b border-zinc-800
              transition-colors
              hover:bg-zinc-900/30
            "
                        >
                            <td className="px-6 py-5">

                                <div>
                                    <h3 className="font-medium">
                                        {finding.title}
                                    </h3>

                                    <p className="mt-1 text-sm text-zinc-400">
                                        {finding.filePath}
                                    </p>
                                </div>

                            </td>

                            <td className="px-6 py-5">
                                <SeverityBadge
                                    severity={finding.severity}
                                />
                            </td>

                            <td className="px-6 py-5">
                                {finding.riskScore}
                            </td>

                            <td className="px-6 py-5">
                                {finding.exploitability}
                            </td>

                            <td className="px-6 py-5">

                                <span
                                    className={`
                  rounded-full px-2.5 py-1
                  text-xs font-medium
                  ${statusStyles(
                                        finding.status
                                    )}
                `}
                                >
                                    {finding.status}
                                </span>

                            </td>
                        </tr>

                    ))}

                </tbody>

            </table>
        </div>
    </div>

    );
}
