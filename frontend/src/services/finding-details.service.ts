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

export async function getFindingById(id: string): Promise<FindingDetails | undefined> {
  const findings: Record<string, FindingDetails> = {
    "1": {
      id: "1",
      title: "SQL Injection vulnerability",
      filePath: "src/api/users.ts",
      severity: "CRITICAL",
      riskScore: 9.8,

      ai_summary:
        "Unsanitized user input reaches SQL query construction.",

      attack_scenario:
        "An attacker can inject SQL payloads through user-controlled parameters and potentially dump or manipulate database records.",

      business_impact:
        "Potential database compromise and unauthorized data access.",

      secure_fix:
        "Use parameterized queries and input validation.",

      developer_steps: [
        "Replace string concatenation",
        "Use prepared statements",
        "Validate input",
      ],

      cwe: "CWE-89",
      owasp: "A03:2021 Injection",
      mitre: "T1190",

      repository: "webgoat-api",
      framework: "Spring Boot",

      code_snippet: `
SELECT * FROM users
WHERE id='${"$"}{userInput}'
      `,
    },

    "2": {
      id: "2",
      title: "Hardcoded JWT secret",
      filePath: ".env",
      severity: "HIGH",
      riskScore: 8.1,

      ai_summary:
        "JWT signing secret is embedded directly in application source.",

      attack_scenario:
        "An attacker obtaining source code access can forge authentication tokens and impersonate users.",

      business_impact:
        "Authentication bypass and unauthorized access.",

      secure_fix:
        "Store secrets in environment variables or dedicated secret management systems.",

      developer_steps: [
        "Remove hardcoded secret",
        "Move secrets to .env",
        "Rotate compromised keys",
      ],

      cwe: "CWE-798",
      owasp:
        "A07:2021 Identification and Authentication Failures",
      mitre: "T1552",

      repository: "auth-service",
      framework: "Node.js",

      code_snippet: `
const JWT_SECRET = "mysecret123";
      `,
    },

    "3": {
      id: "3",
      title: "Insecure deserialization",
      filePath: "serializers.py",
      severity: "MEDIUM",
      riskScore: 6.5,

      ai_summary:
        "Untrusted serialized data is processed without validation.",

      attack_scenario:
        "An attacker may inject malicious payloads that trigger arbitrary code execution or object manipulation.",

      business_impact:
        "Remote code execution and application compromise.",

      secure_fix:
        "Avoid unsafe deserialization methods and validate incoming objects.",

      developer_steps: [
        "Use safe serializers",
        "Validate object structure",
        "Restrict object types",
      ],

      cwe: "CWE-502",
      owasp: "A08:2021 Software and Data Integrity Failures",
      mitre: "T1059",

      repository: "payments-api",
      framework: "Python FastAPI",

      code_snippet: `
pickle.loads(user_input)
      `,
    },
  };

  await new Promise((resolve) =>
    setTimeout(resolve, 500)
  );

  return findings[id];
}

// Backward-compatible alias (older imports)
export const getFinding = getFindingById;
