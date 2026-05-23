"use client";

import { ScanProgress } from "./scan-progress";

export interface ScanCardProps {
    id: string;
    repositoryName: string;
    scanType: string;
    status: "RUNNING" | "COMPLETED" | "FAILED";
    progress: number;
    findingsCount?: number;
    criticalCount?: number;
    startedAt: string;
    duration?: string;
    failureReason?: string;
    onView?: (id: string) => void;
    onRerun?: (id: string) => void;
}

function statusStyles(
    status: ScanCardProps["status"]
) {

    switch (status) {

        case "RUNNING":
            return "bg-blue-500/15 text-blue-400";

        case "COMPLETED":
            return "bg-green-500/15 text-green-400";

        case "FAILED":
            return "bg-red-500/15 text-red-400";

        default:
            return "bg-zinc-500/15 text-zinc-400";

    }

}

export function ScanCard({
    id,
    repositoryName,
    scanType,
    status,
    progress,
    findingsCount,
    criticalCount,
    startedAt,
    duration,
    failureReason,
    onView,
    onRerun,
}: ScanCardProps) {

    return (

        <div
            className="
            rounded-xl
            border
            border-zinc-800
            bg-zinc-950
            p-6
            transition-all
            hover:border-zinc-700
            "
        >

            <div
                className="
                flex
                items-start
                justify-between
                "
            >

                <div>

                    <h3
                        className="
                        text-lg
                        font-semibold
                        text-zinc-100
                        "
                    >
                        {repositoryName}
                    </h3>

                    <p
                        className="
                        mt-1
                        text-sm
                        text-zinc-400
                        "
                    >
                        {scanType}
                    </p>

                </div>


                <span
                    className={`
                    rounded-full
                    px-3
                    py-1
                    text-xs
                    font-medium
                    ${statusStyles(status)}
                    `}
                >
                    {status}
                </span>

            </div>


            <div className="mt-6">

                <ScanProgress
                    progress={progress}
                />

            </div>


            {status === "FAILED" && (
                <div
                    className="
                    mt-6
                    rounded-2xl
                    border
                    border-red-500/10
                    bg-red-500/10
                    p-4
                    "
                >

                    <p
                        className="
                        text-xs
                        font-medium
                        uppercase
                        text-red-300
                        "
                    >
                        Failure Reason
                    </p>

                    <p
                        className="
                        mt-2
                        text-sm
                        text-red-100
                        "
                    >
                        {failureReason ?? "Unknown error"}
                    </p>

                </div>
            )}

            <div
                className="
                mt-6
                grid
                grid-cols-2
                gap-4
                "
            >

                <div>

                    <p
                        className="
                        text-xs
                        text-zinc-500
                        "
                    >
                        Findings
                    </p>

                    <p
                        className="
                        mt-1
                        text-zinc-100
                        "
                    >
                        {status === "COMPLETED"
                            ? findingsCount ?? "-"
                            : "-"}
                    </p>

                </div>


                <div>

                    <p
                        className="
                        text-xs
                        text-zinc-500
                        "
                    >
                        Critical
                    </p>

                    <p
                        className="
                        mt-1
                        text-red-400
                        "
                    >
                        {status === "COMPLETED"
                            ? criticalCount ?? "-"
                            : "-"}
                    </p>

                </div>


                <div>

                    <p
                        className="
                        text-xs
                        text-zinc-500
                        "
                    >
                        Started
                    </p>

                    <p
                        className="
                        mt-1
                        text-zinc-300
                        "
                    >
                        {startedAt}
                    </p>

                </div>


                <div>

                    <p
                        className="
                        text-xs
                        text-zinc-500
                        "
                    >
                        Duration
                    </p>

                    <p
                        className="
                        mt-1
                        text-zinc-300
                        "
                    >
                        {duration ?? "-"}
                    </p>

                </div>

            </div>


            {status === "FAILED" ? (
                <button
                    onClick={() => onRerun?.(id)}
                    className="
                    mt-6
                    w-full
                    rounded-lg
                    bg-red-600
                    px-4
                    py-3
                    text-sm
                    font-medium
                    text-white
                    transition-colors
                    hover:bg-red-700
                    "
                >
                    Re-run Scan
                </button>
            ) : (
                <button
                    onClick={() => onView?.(id)}
                    className="
                    mt-6
                    w-full
                    rounded-lg
                    bg-zinc-900
                    px-4
                    py-3
                    text-sm
                    font-medium
                    text-zinc-100
                    transition-colors
                    hover:bg-zinc-800
                    "
                >
                    View Scan
                </button>
            )}

        </div>

    );

}