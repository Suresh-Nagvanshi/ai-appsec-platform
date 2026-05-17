import { FindingsTable } from "@/components/findings/findings-table";

export default function FindingsPage() {
  return (<div className="space-y-6">

    <div>
      <h1 className="text-3xl font-bold">
        Findings
      </h1>

      <p className="mt-2 text-zinc-400">
        Analyze, prioritize, and remediate security vulnerabilities.
      </p>
    </div>

    <FindingsTable />

  </div>

  );
}
