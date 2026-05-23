"use client";

import { useRouter } from "next/navigation";
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
                Failed to load findings.
            </div>
        );
    }

    const findings = data || [];

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
                                            {finding.title}
                                        </h3>

                                        <p
                                            className="
                                            mt-1
                                            text-sm
                                            text-zinc-400
                                            "
                                        >
                                            {finding.filePath}
                                        </p>

                                    </div>

                                </td>

                                <td className="px-6 py-5">

                                    <SeverityBadge
                                        severity={
                                            finding.severity
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
                                    {finding.riskScore}
                                </td>

                                <td
                                    className="
                                    px-6
                                    py-5
                                    text-zinc-300
                                    "
                                >
                                    {finding.exploitability}
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