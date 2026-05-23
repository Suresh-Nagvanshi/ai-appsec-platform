import api from "@/lib/api";

export interface Finding {
    id: string;
    title: string;
    filePath: string;
    severity: string;
    riskScore: number;
    exploitability: string;
    status: string;
    repository?: string;
    createdAt?: string;
}

export async function getFindings(): Promise<Finding[]> {
    const response = await api.get<Finding[]>("/findings");
    return response.data;
}
