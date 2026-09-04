/**
 * Repositories service
 * ====================
 * Wraps all /api/repositories/* backend endpoints.
 */

import api from "@/lib/api";

export interface Repository {
  id: string;
  name: string;
  url: string;
  provider: string;
  status: "active" | "inactive";
  last_scan: string | null;
  default_branch: string | null;
  created_at: string;
}

export async function listRepositories(): Promise<Repository[]> {
  const res = await api.get<Repository[]>("/api/repositories");
  return res.data;
}

export async function createRepository(payload: {
  name: string;
  url: string;
  provider?: string;
  default_branch?: string;
}): Promise<Repository> {
  const res = await api.post<Repository>("/api/repositories", payload);
  return res.data;
}

export async function getRepository(repoId: string): Promise<Repository> {
  const res = await api.get<Repository>(`/api/repositories/${repoId}`);
  return res.data;
}

export async function deleteRepository(repoId: string): Promise<void> {
  await api.delete(`/api/repositories/${repoId}`);
}
