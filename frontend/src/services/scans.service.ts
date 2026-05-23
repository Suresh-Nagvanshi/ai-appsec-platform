import api from "@/lib/api";

export type ScanStatus =
    | "RUNNING"
    | "COMPLETED"
    | "FAILED"
    | "QUEUED";

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

export interface StartScanResponse {
    scan_id: string;
    status: string;
}

export async function getScans(): Promise<Scan[]> {
    const response = await api.get<Scan[]>("/api/scans");
    return response.data;
}

export async function getScanById(
    id: string
): Promise<Scan | undefined> {
    const response = await api.get<Scan>(`/api/scans/${id}`);
    return response.data;
}

export async function startScan(
    payload: StartScanRequest
): Promise<StartScanResponse> {
    const response = await api.post<StartScanResponse>(
        "/api/scans/start",
        {
            repository_url: payload.repository,
            scan_type: payload.scanType,
        }
    );
    return response.data;
}
