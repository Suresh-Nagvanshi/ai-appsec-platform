"use client";

import { useState } from "react";
import { Activity, ArrowRight, Braces, CheckCircle2, ClipboardCheck, Cloud, Code2, GitPullRequest, Network, Play, ShieldCheck, Terminal, UploadCloud } from "lucide-react";
import { analyzeApiContract, analyzeInfrastructure, analyzeRuntimePosture, analyzeSupplyChain, discoverEndpoints, evaluateAiModel, evaluateCiGate, evaluateRegressionTests, generateRegressionTests, getSarif, getSecurityGraph, mapApiTop10, runAiSecurityTest, runValidationSandbox, testApiAuthorization, createFixPullRequest } from "@/services/security-tools.service";

type Mode = "api" | "ai" | "operations";
type Tool = "discover" | "mapping" | "authz" | "contract" | "ai-test" | "ai-eval" | "graph" | "regression" | "supply" | "infrastructure" | "sandbox" | "ci" | "runtime" | "fix";

const apiTools: Array<{ id: Tool; label: string; icon: typeof Network }> = [
  { id: "discover", label: "Endpoint discovery", icon: Network },
  { id: "mapping", label: "OWASP API mapping", icon: ShieldCheck },
  { id: "authz", label: "Auth and access probe", icon: ClipboardCheck },
  { id: "contract", label: "Contract analysis", icon: Braces },
];
const aiTools = [
  { id: "ai-test" as Tool, label: "Security probes", icon: ShieldCheck },
  { id: "ai-eval" as Tool, label: "Golden-set evaluation", icon: ClipboardCheck },
];
const operationTools = [
  { id: "graph" as Tool, label: "Security graph", icon: Network },
  { id: "regression" as Tool, label: "Regression tests", icon: CheckCircle2 },
  { id: "supply" as Tool, label: "Supply chain", icon: UploadCloud },
  { id: "infrastructure" as Tool, label: "Infrastructure", icon: Cloud },
  { id: "sandbox" as Tool, label: "Exploit sandbox", icon: Terminal },
  { id: "ci" as Tool, label: "CI gate and SARIF", icon: Code2 },
  { id: "runtime" as Tool, label: "Runtime posture", icon: Activity },
  { id: "fix" as Tool, label: "Fix pull request", icon: GitPullRequest },
];

function Field({ label, value, onChange, placeholder, multiline = false }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string; multiline?: boolean }) {
  const className = "w-full rounded-xl border border-slate-700 bg-slate-950/80 px-3 py-2.5 text-sm text-slate-100 outline-none transition focus:border-amber-300/70 focus:ring-2 focus:ring-amber-300/10";
  return <label className="block space-y-1.5"><span className="text-xs font-medium text-slate-400">{label}</span>{multiline ? <textarea rows={8} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} className={`${className} resize-y font-mono text-xs`} /> : <input value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} className={className} />}</label>;
}

function ActionButton({ children, onClick, disabled = false }: { children: React.ReactNode; onClick: () => void; disabled?: boolean }) {
  return <button type="button" onClick={onClick} disabled={disabled} className="inline-flex h-10 items-center gap-2 rounded-xl bg-amber-300 px-4 text-sm font-semibold text-slate-950 transition hover:bg-amber-200 disabled:pointer-events-none disabled:opacity-50"><Play className="h-4 w-4" />{children}</button>;
}

function Output({ value, error }: { value: unknown; error: string | null }) {
  if (error) return <div role="alert" className="rounded-xl border border-red-400/25 bg-red-400/[0.06] p-4 text-sm text-red-200">{error}</div>;
  if (!value) return <div className="rounded-xl border border-dashed border-slate-800 px-5 py-12 text-center text-sm text-slate-600">Run a tool to inspect its results here.</div>;
  return <pre className="max-h-[520px] overflow-auto rounded-xl border border-slate-800 bg-[#090d12] p-4 font-mono text-xs leading-5 text-slate-300">{JSON.stringify(value, null, 2)}</pre>;
}

export function SecurityToolsWorkbench({ mode }: { mode: Mode }) {
  const tools = mode === "api" ? apiTools : mode === "ai" ? aiTools : operationTools;
  const [tool, setTool] = useState<Tool>(tools[0].id);
  const [projectPath, setProjectPath] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [scanId, setScanId] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [jsonInput, setJsonInput] = useState("{}");
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  async function run(action: () => Promise<unknown>) {
    setRunning(true); setError(null); setResult(null);
    try { setResult(await action()); } catch (cause) { setError(cause instanceof Error ? cause.message : "The request failed"); } finally { setRunning(false); }
  }

  function parseJson() {
    try { return JSON.parse(jsonInput); } catch { throw new Error("Enter valid JSON before running this tool."); }
  }

  function execute() {
    if (tool === "discover") return run(() => discoverEndpoints(projectPath));
    if (tool === "mapping") return run(() => mapApiTop10(projectPath));
    if (tool === "authz") return run(() => testApiAuthorization({ base_url: baseUrl, endpoints: parseJson() }));
    if (tool === "contract") { const value = parseJson(); return run(() => analyzeApiContract(value.spec ?? value, value.baseline)); }
    if (tool === "ai-test") return run(() => runAiSecurityTest({ target_url: targetUrl, request_template: parseJson() }));
    if (tool === "ai-eval") return run(() => evaluateAiModel({ target_url: targetUrl, cases: parseJson() }));
    if (tool === "graph") return run(() => getSecurityGraph(scanId || undefined));
    if (tool === "regression") return run(() => generateRegressionTests(scanId));
    if (tool === "supply") return run(() => analyzeSupplyChain(projectPath));
    if (tool === "infrastructure") return run(() => analyzeInfrastructure(projectPath));
    if (tool === "sandbox") return run(() => runValidationSandbox({ project_path: projectPath, command: parseJson() }));
    if (tool === "ci") return run(() => evaluateCiGate(scanId));
    if (tool === "runtime") return run(() => analyzeRuntimePosture(parseJson()));
    return run(() => createFixPullRequest(parseJson()));
  }

  function executeSecondary() {
    if (tool === "regression") return run(() => evaluateRegressionTests(scanId));
    if (tool === "ci") return run(() => getSarif(scanId));
    return undefined;
  }

  const selected = tools.find((item) => item.id === tool) ?? tools[0];
  return <div className="mx-auto w-full max-w-[1500px] space-y-6">
    <div className="border-b border-slate-800/80 pb-6"><p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-amber-300">Security tools</p><h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-100">{mode === "api" ? "API security" : mode === "ai" ? "AI and ML security" : "Security operations"}</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">Run bounded assessments, inspect evidence, and export results from one authenticated workspace.</p></div>
    <div className="grid gap-5 lg:grid-cols-[250px_minmax(0,1fr)]">
      <nav className="flex gap-1 overflow-x-auto rounded-2xl border border-slate-800 bg-[#111820]/90 p-2 lg:block lg:space-y-1 lg:overflow-visible">{tools.map((item) => { const Icon = item.icon; return <button type="button" key={item.id} onClick={() => { setTool(item.id); setResult(null); setError(null); }} className={`flex min-w-max items-center gap-3 rounded-xl px-3 py-2.5 text-left text-sm transition lg:w-full ${tool === item.id ? "bg-amber-300/12 text-amber-200" : "text-slate-500 hover:bg-slate-800/60 hover:text-slate-200"}`}><Icon className="h-4 w-4" />{item.label}</button>; })}</nav>
      <main className="min-w-0 space-y-5"><section className="rounded-2xl border border-slate-800 bg-[#111820]/90 p-5 shadow-xl shadow-black/10"><div className="mb-5 flex items-start justify-between gap-4"><div><h2 className="text-lg font-semibold text-slate-100">{selected.label}</h2><p className="mt-1 text-sm text-slate-500">{tool === "discover" || tool === "mapping" || tool === "supply" || tool === "infrastructure" ? "Use a managed repository path under repos, uploads, or extracted." : "Provide the target or evidence required for this assessment."}</p></div><ArrowRight className="mt-1 h-5 w-5 text-slate-700" /></div>
        <div className="grid gap-4 md:grid-cols-2">
          {(tool === "discover" || tool === "mapping" || tool === "supply" || tool === "infrastructure" || tool === "sandbox") && <Field label="Managed project path" value={projectPath} onChange={setProjectPath} placeholder="D:/AI SECURITY AGENT - Documents/repos/example" />}
          {(tool === "authz") && <Field label="Authorized public API base URL" value={baseUrl} onChange={setBaseUrl} placeholder="https://api.example.com" />}
          {(tool === "ai-test" || tool === "ai-eval") && <Field label="Model endpoint URL" value={targetUrl} onChange={setTargetUrl} placeholder="https://model.example.com/v1/chat" />}
          {(tool === "graph" || tool === "regression" || tool === "ci") && <Field label="Scan ID" value={scanId} onChange={setScanId} placeholder="Paste a completed scan ID" />}
        </div>
        {(tool === "authz" || tool === "contract" || tool === "ai-test" || tool === "ai-eval" || tool === "sandbox" || tool === "runtime" || tool === "fix") && <div className="mt-4"><Field label={tool === "authz" ? "Endpoint inventory JSON" : tool === "contract" ? "OpenAPI JSON (or { spec, baseline })" : tool === "ai-test" ? "Request template JSON" : tool === "ai-eval" ? "Evaluation cases JSON" : tool === "sandbox" ? "Command JSON array" : tool === "runtime" ? "Runtime asset JSON array" : "Pull-request request JSON"} value={jsonInput} onChange={setJsonInput} multiline placeholder="{}" /></div>}
        <div className="mt-5 flex flex-wrap items-center gap-3"><ActionButton onClick={execute} disabled={running}>{running ? "Running..." : "Run assessment"}</ActionButton>{(tool === "regression" || tool === "ci") && <button type="button" onClick={executeSecondary} disabled={running || !scanId} className="inline-flex h-10 items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 text-sm font-medium text-slate-300 transition hover:border-slate-600 hover:bg-slate-800 disabled:pointer-events-none disabled:opacity-50">{tool === "ci" ? "Fetch SARIF" : "Evaluate current scan"}</button>}<span className="text-xs text-slate-600">Results stay in this workspace until you export or copy them.</span></div>
      </section><section><div className="mb-2 flex items-center justify-between"><h3 className="text-sm font-semibold text-slate-200">Assessment output</h3>{result !== null && <span className="inline-flex items-center gap-1.5 text-xs text-emerald-300"><CheckCircle2 className="h-3.5 w-3.5" />Response received</span>}</div><Output value={result} error={error} /></section></main>
    </div>
  </div>;
}
