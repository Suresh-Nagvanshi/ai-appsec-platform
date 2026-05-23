"use client";

interface TimelineStep {
    id: string;
    title: string;
    status: "COMPLETED" | "RUNNING" | "PENDING";
}

interface ScanTimelineProps {
    steps: TimelineStep[];
}

function statusStyles(
    status: TimelineStep["status"]
) {

    switch (status) {

        case "COMPLETED":
            return "bg-green-500";

        case "RUNNING":
            return "bg-red-500";

        case "PENDING":
            return "bg-zinc-700";

        default:
            return "bg-zinc-700";
    }
}

export function ScanTimeline({
    steps
}: ScanTimelineProps) {

    return (

        <div
            className="
            rounded-xl
            border
            border-zinc-800
            bg-zinc-950
            p-6
            "
        >

            <h2
                className="
                mb-6
                text-lg
                font-semibold
                "
            >
                Scan Timeline
            </h2>

            <div className="space-y-5">

                {steps.map(
                    (step) => (

                        <div
                            key={step.id}
                            className="
                            flex
                            items-center
                            gap-4
                            "
                        >

                            <div
                                className={`
                                h-3
                                w-3
                                rounded-full
                                ${statusStyles(
                                    step.status
                                )}
                                `}
                            />

                            <div>

                                <p
                                    className="
                                    text-sm
                                    font-medium
                                    "
                                >
                                    {step.title}
                                </p>

                                <p
                                    className="
                                    text-xs
                                    text-zinc-400
                                    "
                                >
                                    {step.status}
                                </p>

                            </div>

                        </div>

                    )
                )}

            </div>

        </div>

    );

}