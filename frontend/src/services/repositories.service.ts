import api from "@/lib/api";

export type RepositoryProvider =
    | "GitHub"
    | "GitLab"
    | "Bitbucket";

export interface Repository {
    id: string;
    name: string;
    provider: RepositoryProvider;
    status: "CONNECTED" | "DISCONNECTED";
    url: string;
    lastScan?: string;
}

export async function getRepositories(): Promise<Repository[]> {
    const response = await api.get<Repository[]>("/api/repositories");
    return response.data;
}

export async function addRepository(
    repository: Omit<Repository, "id">
): Promise<Repository> {
    const response = await api.post<Repository>(
        "/api/repositories",
        repository
    );
    return response.data;
}
