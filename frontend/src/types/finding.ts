export interface Finding {
id: string;

title: string;

severity:
| "CRITICAL"
| "HIGH"
| "MEDIUM"
| "LOW"
| "INFO";

riskScore: number;

exploitability:
| "Very High"
| "High"
| "Medium"
| "Low";

repository: string;

filePath: string;

status:
| "OPEN"
| "IN_PROGRESS"
| "RESOLVED";

createdAt: string;
}
