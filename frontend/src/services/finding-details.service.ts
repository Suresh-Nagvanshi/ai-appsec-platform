import api from "@/lib/api";
import type { Finding } from "@/types/finding";

export type FindingDetails = Finding & {
    ai_summary?: string;
    attack_scenario?: string;
    business_impact?: string;
    secure_fix?: string;
    developer_steps?: string[];
    cwe?: string;
    owasp?: string;
    mitre?: string;
    framework?: string;
    repository?: string;
    code_snippet?: string;
    snippet?: string;
};

export async function getFindingById(
    id: string
): Promise<FindingDetails | undefined> {
    const response = await api.get<FindingDetails>(
        `/findings/${id}`
    );
    return response.data;
}

// Backward-compatible alias (older imports)
export const getFinding = getFindingById;
