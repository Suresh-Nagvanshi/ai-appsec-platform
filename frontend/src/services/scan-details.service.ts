export type TimelineStatus =
    | "PENDING"
    | "RUNNING"
    | "COMPLETED"
    | "FAILED";

export interface TimelineStep {
    id: string;
    title: string;
    status: TimelineStatus;
}

export interface ScanLog {
    id: string;
    time: string;
    level: "INFO" | "WARNING" | "ERROR";
    message: string;
}

export interface ScanSummary {
    critical: number;
    high: number;
    medium: number;
    low: number;
}

export interface ScanDetails {
    id: string;
    summary: ScanSummary;
    timeline: TimelineStep[];
    logs: ScanLog[];
}

const scanStore: Record<
    string,
    {
        stepIndex: number;
        logs: ScanLog[];
    }
> = {};

const stages = [

    "Repository Imported",
    "Static Analysis",
    "Dependency Scan",
    "AI Analysis",
    "Report Generation"

];

const stageMessages = [

    "Repository cloned successfully",
    "Semgrep analysis running",
    "Checking dependencies",
    "Running AI vulnerability analysis",
    "Generating security report"

];

function getTime() {

    return new Date().toLocaleTimeString(
        [],
        {
            hour12: false
        }
    );

}

export async function getScanDetails(
    scanId: string
): Promise<ScanDetails> {

    await new Promise(
        resolve =>
            setTimeout(resolve, 300)
    );

    if (!scanStore[scanId]) {

        scanStore[scanId] = {

            stepIndex: 0,

            logs: [
                {
                    id: crypto.randomUUID(),
                    time: getTime(),
                    level: "INFO",
                    message: "Starting scan"
                }
            ]

        };

    }

    const scan = scanStore[scanId];

    if (
        scan.stepIndex <
        stages.length
    ) {

        scan.logs.push({

            id: crypto.randomUUID(),

            time: getTime(),

            level: "INFO",

            message:
                stageMessages[
                scan.stepIndex
                ]

        });

        scan.stepIndex++;

    }

    const timeline: TimelineStep[] =
        stages.map(
            (
                stage,
                index
            ): TimelineStep => ({

                id: String(index),

                title: stage,

                status:
                    index < scan.stepIndex
                        ? "COMPLETED"
                        : index === scan.stepIndex
                            ? "RUNNING"
                            : "PENDING"

            })
        );

    const completed =
        scan.stepIndex;

    const summary = {

        critical:
            completed >= 5
                ? Math.floor(
                    Math.random() * 4
                )
                : 0,

        high:
            completed >= 5
                ? Math.floor(
                    Math.random() * 10
                )
                : 0,

        medium:
            completed >= 5
                ? Math.floor(
                    Math.random() * 15
                )
                : 0,

        low:
            completed >= 5
                ? Math.floor(
                    Math.random() * 10
                )
                : 0

    };

    return {

        id: scanId,

        summary,

        timeline,

        logs: scan.logs

    };

}