import api from "@/lib/api";

export type Endpoint = { framework: string; method: string; path: string; file: string };
export type ApiFinding = { category: string; severity: string; location?: string; message: string };

export async function discoverEndpoints(project_path: string) {
  const response = await api.post<{ project_path: string; total: number; endpoints: Endpoint[] }>("/api/api-security/endpoints", { project_path });
  return response.data;
}

export async function mapApiTop10(project_path: string) {
  const response = await api.post<{ total: number; category_counts: Record<string, number>; endpoints: Array<Endpoint & { owasp_api: Array<{ id: string; name: string; confidence: string; rationale: string }> }> }>("/api/api-security/mapping", { project_path });
  return response.data;
}

export async function testApiAuthorization(payload: { base_url: string; endpoints: Endpoint[]; headers?: Record<string, string> }) {
  const response = await api.post<{ tested: number; results: Array<Record<string, unknown>> }>("/api/api-security/authz-test", payload);
  return response.data;
}

export async function analyzeApiContract(spec: object, baseline?: object) {
  const response = await api.post<Record<string, unknown>>("/api/api-security/contract", { spec, baseline });
  return response.data;
}

export async function runAiSecurityTest(payload: Record<string, unknown>) {
  const response = await api.post<Record<string, unknown>>("/api/ai-security/test", payload);
  return response.data;
}

export async function evaluateAiModel(payload: Record<string, unknown>) {
  const response = await api.post<Record<string, unknown>>("/api/ai-security/evaluate", payload);
  return response.data;
}

export async function getSecurityGraph(scan_id?: string) {
  const response = await api.get<Record<string, unknown>>("/api/security-graph", { params: scan_id ? { scan_id } : undefined });
  return response.data;
}

export async function generateRegressionTests(scan_id: string) {
  const response = await api.post<Record<string, unknown>>("/api/regression-tests/generate", { scan_id });
  return response.data;
}

export async function evaluateRegressionTests(scan_id: string) {
  const response = await api.post<Record<string, unknown>>("/api/regression-tests/evaluate", { scan_id });
  return response.data;
}

export async function analyzeSupplyChain(project_path: string, include_secrets = true) {
  const response = await api.post<Record<string, unknown>>("/api/supply-chain/analyze", { project_path, include_secrets });
  return response.data;
}

export async function analyzeInfrastructure(project_path: string) {
  const response = await api.post<Record<string, unknown>>("/api/infrastructure/analyze", { project_path });
  return response.data;
}

export async function runValidationSandbox(payload: Record<string, unknown>) {
  const response = await api.post<Record<string, unknown>>("/api/validation-sandbox/run", payload);
  return response.data;
}

export async function evaluateCiGate(scan_id: string, minimum_severity = "HIGH") {
  const response = await api.post<Record<string, unknown>>("/api/ci/gate", { scan_id, minimum_severity });
  return response.data;
}

export async function getSarif(scan_id: string) {
  const response = await api.get<Record<string, unknown>>(`/api/ci/sarif/${scan_id}`);
  return response.data;
}

export async function analyzeRuntimePosture(assets: unknown[]) {
  const response = await api.post<Record<string, unknown>>("/api/runtime-security/posture", { assets });
  return response.data;
}

export async function createFixPullRequest(payload: Record<string, unknown>) {
  const response = await api.post<Record<string, unknown>>("/api/fix/pull-request", payload);
  return response.data;
}
