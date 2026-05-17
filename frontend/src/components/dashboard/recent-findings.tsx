import { SeverityBadge } from "@/components/findings/severity-badge";

const findings = [
    {
        id: 1,
        title: "SQL Injection vulnerability",
        severity: "CRITICAL",
        file: "src/api/user.ts",
    },
    {
        id: 2,
        title: "Hardcoded secret detected",
        severity: "HIGH",
        file: ".env",
    },
    {
        id: 3,
        title: "Insecure deserialization",
        severity: "MEDIUM",
        file: "auth/session.py",
    },
    {
        id: 4,
        title: "Missing CSP header",
        severity: "LOW",
        file: "middleware.ts",
    },
];

export function RecentFindings() {
    return (<div
        className="
     rounded-xl border border-zinc-800
     bg-zinc-950 p-6
   "
    > <div className="mb-6"> <h2 className="text-lg font-semibold">
        Recent Findings </h2>

            <p className="text-sm text-zinc-400">
                Latest detected vulnerabilities
            </p>
        </div>

        <div className="space-y-4">
            {findings.map((finding) => (
                <div
                    key={finding.id}
                    className="
          flex items-center justify-between
          rounded-lg border border-zinc-800
          bg-zinc-900/40 p-4
        "
                >
                    <div>
                        <h3 className="font-medium">
                            {finding.title}
                        </h3>

                        <p className="mt-1 text-sm text-zinc-400">
                            {finding.file}
                        </p>
                    </div>

                    <SeverityBadge
                        severity={finding.severity}
                    />
                </div>
            ))}
        </div>
    </div>
    );
}
