import api from "@/lib/api";
import type { Finding } from "@/types/finding";

export type FindingDetails = Finding & {
    created_at?: string;
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
    risk_summary?: {
        max_risk_score?: number;
        average_risk_score?: number;
        highest_priority?: string;
    };
    representative_finding?: {
        finding?: {
            message?: string;
            check_id?: string;
            rule_id?: string;
            path?: string;
            severity?: string;
            cwe?: string[];
            owasp?: string[];
            extra?: {
                severity?: string;
                metadata?: { cwe?: string[]; owasp?: string[] };
            };
        };
        framework?: { primary_framework?: string };
        snippet?: { vulnerable_line?: string };
        metadata?: { project_path?: string; language?: string };
        risk?: { exploitability?: string; severity?: string; risk_score?: number };
        ai_analysis?: {
            summary?: string;
            attack_scenario?: string;
            business_impact?: string;
            secure_fix?: string;
            developer_remediation_steps?: string[];
            mitre_attack_mapping?: string[];
        };
    };
};

export async function getFindingById(
    id: string
): Promise<FindingDetails | undefined> {
    const response = await api.get<FindingDetails>(
        `/findings/${id}`
    );
    const finding = response.data;
    const representative = finding.representative_finding;
    const scannerFinding = representative?.finding;
    const risk = representative?.risk;
    const aiAnalysis = representative?.ai_analysis;

    return {
        ...finding,
        title:
            finding.title ||
            scannerFinding?.message ||
            scannerFinding?.rule_id ||
            "Security finding",
        severity: finding.severity || risk?.severity || scannerFinding?.severity,
        riskScore: finding.riskScore ?? risk?.risk_score ?? finding.risk_summary?.max_risk_score ?? 0,
        filePath: finding.filePath || scannerFinding?.path || "",
        repository: finding.repository || representative?.metadata?.project_path || "",
        createdAt: finding.createdAt || finding.created_at || "",
        cwe: finding.cwe || scannerFinding?.cwe?.[0],
        owasp: finding.owasp || scannerFinding?.owasp?.[0],
        mitre: finding.mitre || aiAnalysis?.mitre_attack_mapping?.[0],
        ai_summary: finding.ai_summary || aiAnalysis?.summary,
        attack_scenario: finding.attack_scenario || aiAnalysis?.attack_scenario,
        business_impact: finding.business_impact || aiAnalysis?.business_impact,
        secure_fix: finding.secure_fix || aiAnalysis?.secure_fix,
        developer_steps:
            finding.developer_steps || aiAnalysis?.developer_remediation_steps,
        framework:
            finding.framework || representative?.framework?.primary_framework,
        code_snippet:
            finding.code_snippet || representative?.snippet?.vulnerable_line,
    };
}

// Backward-compatible alias (older imports)
export const getFinding = getFindingById;
