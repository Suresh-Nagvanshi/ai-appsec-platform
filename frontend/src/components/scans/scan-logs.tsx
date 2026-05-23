"use client";

interface ScanLog {
    id: string;
    timestamp: string;
    message: string;
    level: "INFO" | "WARNING" | "ERROR";
}

interface ScanLogsProps {
    logs: ScanLog[];
}

function levelStyles(
    level: ScanLog["level"]
) {

    switch (level) {

        case "INFO":
            return "text-blue-400";

        case "WARNING":
            return "text-yellow-400";

        case "ERROR":
            return "text-red-400";

        default:
            return "text-zinc-400";

    }

}

export function ScanLogs({
    logs
}: ScanLogsProps) {

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
                Scan Logs
            </h2>

            <div
                className="
                max-h-[350px]
                overflow-y-auto
                space-y-4
                rounded-lg
                bg-black
                p-4
                border
                border-zinc-800
                "
            >

                {logs.map(
                    (log) => (

                        <div
                            key={log.id}
                            className="
                            flex
                            gap-4
                            text-sm
                            border-b
                            border-zinc-900
                            pb-3
                            "
                        >

                            <span
                                className="
                                text-zinc-500
                                min-w-[80px]
                                "
                            >
                                {log.timestamp}
                            </span>

                            <span
                                className={`
                                min-w-[80px]
                                font-medium
                                ${levelStyles(
                                    log.level
                                )}
                                `}
                            >
                                {log.level}
                            </span>

                            <span
                                className="
                                text-zinc-300
                                "
                            >
                                {log.message}
                            </span>

                        </div>

                    )
                )}

                {logs.length === 0 && (

                    <div
                        className="
                        py-10
                        text-center
                        text-zinc-500
                        "
                    >
                        No logs available
                    </div>

                )}

            </div>

        </div>

    );

}