import api from "@/lib/api";

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

export async function getScanDetails(
    scanId: string
): Promise<ScanDetails> {
    const response = await api.get<ScanDetails>(
        `/api/scans/${scanId}/status`
    );
    return response.data;
}
