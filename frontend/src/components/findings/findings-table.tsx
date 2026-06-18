"use client";

import { useRouter } from "next/navigation";
import { useFindings } from "@/hooks/useFindings";
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
    const router = useRouter();

    const {
        data,
        isLoading,
        error,
    } = useFindings();

    if (isLoading) {
        return (
            <div
                className="
                rounded-xl
                border border-zinc-800
                bg-zinc-950
                p-6
                text-zinc-400
                "
            >
                Loading findings...
            </div>
        );
    }

    if (error) {
        return (
            <div
                className="
                rounded-xl
                border border-red-500/20
                bg-zinc-950
                p-6
                text-red-400
                "
            >
                Failed to load findings. Ensure the backend is running and reachable.
            </div>
        );
    }

    const findings = data?.findings || [];

    if (findings.length === 0) {
        return (
            <div
                className="
                rounded-xl
                border border-zinc-800
                bg-zinc-950
                p-12
                text-center
                "
            >
                <p className="text-zinc-400 font-medium">No findings yet.</p>
                <p className="mt-1 text-sm text-zinc-500">
                    Run a GitHub or ZIP scan to see security vulnerabilities here.
                </p>
            </div>
        );
    }

    return (
        <div
            className="
            overflow-hidden
            rounded-xl
            border
            border-zinc-800
            bg-zinc-950
            "
        >
            <div
                className="
                border-b
                border-zinc-800
                p-6
                "
            >
                <h2
                    className="
                    text-lg
                    font-semibold
                    text-zinc-100
                    "
                >
                    Findings
                </h2>

                <p
                    className="
                    mt-1
                    text-sm
                    text-zinc-400
                    "
                >
                    Security vulnerabilities detected across repositories
                </p>
            </div>

            <div className="overflow-x-auto">

                <table className="w-full">

                    <thead
                        className="
                        border-b
                        border-zinc-800
                        bg-zinc-900/40
                        "
                    >
                        <tr
                            className="
                            text-left
                            text-sm
                            text-zinc-400
                            "
                        >
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
                                onClick={() =>
                                    router.push(
                                        `/findings/${finding.id}`
                                    )
                                }
                                className="
                                cursor-pointer
                                border-b
                                border-zinc-800
                                transition-all
                                hover:bg-zinc-900/40
                                "
                            >

                                <td className="px-6 py-5">

                                    <div>

                                        <h3
                                            className="
                                            font-medium
                                            text-zinc-100
                                            "
                                        >
                                            {finding.representative_finding?.finding?.check_id || "Untitled"}
                                        </h3>

                                        <p
                                            className="
                                            mt-1
                                            text-sm
                                            text-zinc-400
                                            "
                                        >
                                            {finding.representative_finding?.finding?.path || "—"}
                                        </p>

                                    </div>

                                </td>

                                <td className="px-6 py-5">

                                    <SeverityBadge
                                        severity={
                                            finding.representative_finding?.finding?.extra?.severity ||
                                            finding.representative_finding?.risk?.severity ||
                                            "UNKNOWN"
                                        }
                                    />

                                </td>

                                <td
                                    className="
                                    px-6
                                    py-5
                                    text-zinc-300
                                    "
                                >
                                    {finding.risk_summary?.max_risk_score ?? "—"}
                                </td>

                                <td
                                    className="
                                    px-6
                                    py-5
                                    text-zinc-300
                                    "
                                >
                                    {finding.representative_finding?.risk?.exploitability ?? "—"}
                                </td>

                                <td className="px-6 py-5">

                                    <span
                                        className={`
                                        rounded-full
                                        px-2.5
                                        py-1
                                        text-xs
                                        font-medium
                                        ${statusStyles(
                                            (finding.status || "open").toUpperCase()
                                        )}
                                        `}
                                    >
                                        {(finding.status || "open").toUpperCase()}
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
