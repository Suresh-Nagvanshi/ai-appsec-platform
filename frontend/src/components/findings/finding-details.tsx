"use client";

import { useFinding } from "@/hooks/use-finding";
import { SeverityBadge } from "./severity-badge";
import { FindingTabs } from "./finding-tabs";

interface Props {
    id: string;
}

export function FindingDetails({
    id,
}: Props) {

    const {
        data,
        isLoading,
        error,
    } = useFinding(id);

    if (isLoading) {
        return (
            <div
                className="
                rounded-xl
                border
                border-zinc-800
                bg-zinc-950
                p-6
                text-zinc-400
                "
            >
                Loading finding...
            </div>
        );
    }

    if (error || !data) {
        return (
            <div
                className="
                rounded-xl
                border
                border-red-500/20
                bg-zinc-950
                p-6
                text-red-400
                "
            >
                Failed to load finding
            </div>
        );
    }

    return (

        <div
            className="
            space-y-6
            "
        >

            {/* Header */}

            <div
                className="
                rounded-xl
                border
                border-zinc-800
                bg-zinc-950
                p-6
                "
            >

                <div
                    className="
                    flex
                    justify-between
                    items-start
                    "
                >

                    <div>

                        <h1
                            className="
                            text-3xl
                            font-bold
                            text-zinc-100
                            "
                        >
                            {data.title || "Untitled"}
                        </h1>

                        <p
                            className="
                            mt-2
                            text-zinc-400
                            "
                        >
                            {data.filePath || "—"}
                        </p>

                    </div>

                    <SeverityBadge
                        severity={
                            data.severity || "UNKNOWN"
                        }
                    />

                </div>


                <div
                    className="
                    mt-6
                    flex
                    flex-wrap
                    gap-3
                    "
                >

                    <div
                        className="
                        rounded-full
                        bg-zinc-900
                        px-4
                        py-2
                        text-sm
                        "
                    >
                        Risk:

                        <span
                            className="
                            ml-2
                            text-red-400
                            "
                        >
                            {data.risk_summary?.max_risk_score ?? "—"}
                        </span>

                    </div>


                    <div
                        className="
                        rounded-full
                        bg-zinc-900
                        px-4
                        py-2
                        text-sm
                        "
                    >
                        {data.cwe || "No CWE"}
                    </div>


                    <div
                        className="
                        rounded-full
                        bg-zinc-900
                        px-4
                        py-2
                        text-sm
                        "
                    >
                        {data.owasp || "No OWASP"}
                    </div>


                    <div
                        className="
                        rounded-full
                        bg-zinc-900
                        px-4
                        py-2
                        text-sm
                        "
                    >
                        MITRE:
                        {" "}
                        {data.representative_finding?.ai_analysis?.mitre_attack_mapping?.[0] || "No MITRE"}
                    </div>

                </div>

            </div>


            {/* Tabs */}

            <FindingTabs
                data={data}
            />


            {/* Actions */}

            <div
                className="
                flex
                flex-wrap
                gap-4
                "
            >

                <button
                    className="
                    rounded-lg
                    bg-red-600
                    px-5
                    py-3
                    font-medium
                    transition-colors
                    hover:bg-red-700
                    "
                >
                    Mark Resolved
                </button>


                <button
                    className="
                    rounded-lg
                    bg-zinc-800
                    px-5
                    py-3
                    font-medium
                    transition-colors
                    hover:bg-zinc-700
                    "
                >
                    Export Report
                </button>


                <button
                    className="
                    rounded-lg
                    bg-zinc-800
                    px-5
                    py-3
                    font-medium
                    transition-colors
                    hover:bg-zinc-700
                    "
                >
                    Re-run Scan
                </button>

            </div>

        </div>

    );
}