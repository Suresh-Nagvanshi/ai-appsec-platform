export type ScanStatus =
    | "RUNNING"
    | "COMPLETED"
    | "FAILED";

export interface Scan {
    id: string;
    repositoryName: string;
    scanType: string;
    status: ScanStatus;
    progress: number;
    findingsCount?: number;
    criticalCount?: number;
    startedAt: string;
    duration?: string;
    failureReason?: string;
}

export interface StartScanRequest {
    repository: string;
    scanType: string;
}

const STORAGE_KEY = "ai-appsec-scans";

const defaultScans: Scan[] = [

    {
        id: "1",
        repositoryName: "WebGoat",
        scanType: "Full Scan",
        status: "RUNNING",
        progress: 62,
        findingsCount: 15,
        criticalCount: 4,
        startedAt: "2 mins ago",
        duration: "-"
    },

    {
        id: "2",
        repositoryName: "Varsity_Vibe",
        scanType: "Static Analysis",
        status: "COMPLETED",
        progress: 100,
        findingsCount: 21,
        criticalCount: 3,
        startedAt: "15 mins ago",
        duration: "3m 28s"
    },

    {
        id: "3",
        repositoryName: "AdreliaERP",
        scanType: "Dependency Analysis",
        status: "FAILED",
        progress: 74,
        findingsCount: 0,
        criticalCount: 0,
        startedAt: "30 mins ago",
        duration: "1m 12s"
    }

];

function loadScans(): Scan[] {
    if (typeof window === "undefined") {
        return [...defaultScans];
    }

    const raw = window.localStorage.getItem(
        STORAGE_KEY
    );

    if (!raw) {
        return [...defaultScans];
    }

    try {
        const parsed = JSON.parse(raw);

        if (!Array.isArray(parsed)) {
            return [...defaultScans];
        }

        return parsed;
    } catch {
        return [...defaultScans];
    }
}

function saveScans(scans: Scan[]) {
    if (typeof window === "undefined") {
        return;
    }

    window.localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify(scans)
    );
}

export async function getScans(): Promise<Scan[]> {

    await new Promise(
        (resolve) =>
            setTimeout(resolve, 600)
    );

    return loadScans();
}

export async function getScanById(
    id: string
): Promise<Scan | undefined> {

    await new Promise(
        (resolve) =>
            setTimeout(resolve, 300)
    );

    return loadScans().find(
        (scan) => scan.id === id
    );

}

export async function startScan(
    payload: StartScanRequest
): Promise<Scan> {

    await new Promise(
        (resolve)=>
            setTimeout(resolve,500)
    );

    const newScan: Scan = {

        id:
            crypto.randomUUID(),

        repositoryName:
            payload.repository,

        scanType:
            payload.scanType,

        status:
            "RUNNING",

        progress:
            0,

        startedAt:
            "Just now",

        duration:
            "-"

    };

    const existingScans =
        await getScans();

    const updatedScans = [

        newScan,
        ...existingScans

    ];

    saveScans(
        updatedScans
    );

    return newScan;

}

export { loadScans, saveScans };
