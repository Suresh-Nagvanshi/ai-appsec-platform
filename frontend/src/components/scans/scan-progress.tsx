"use client";

interface ScanProgressProps {
    progress: number;
}

export function ScanProgress({
    progress,
}: ScanProgressProps) {

    const normalizedProgress = Math.max(
        0,
        Math.min(progress, 100)
    );

    return (

        <div
            className="
            w-full
            space-y-2
            "
        >

            <div
                className="
                flex
                items-center
                justify-between
                "
            >

                <span
                    className="
                    text-xs
                    text-zinc-400
                    "
                >
                    Progress
                </span>

                <span
                    className="
                    text-xs
                    font-medium
                    text-zinc-300
                    "
                >
                    {normalizedProgress}%
                </span>

            </div>


            <div
                className="
                h-2
                w-full
                overflow-hidden
                rounded-full
                bg-zinc-900
                "
            >

                <div
                    className="
                    h-full
                    rounded-full
                    bg-red-500
                    transition-all
                    duration-500
                    "
                    style={{
                        width: `${normalizedProgress}%`,
                    }}
                />

            </div>

        </div>

    );

}