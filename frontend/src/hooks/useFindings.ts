/**
 * useFindings & useFinding
 * ========================
 * React Query hooks for findings data.
 * useFindings: paginated list with filters
 * useFinding:  single finding detail
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getFindings,
  getFinding,
  updateFindingStatus,
  Finding,
} from "@/services/findings.service";

interface FindingsFilter {
  scan_id?: string;
  severity?: string;
  status?: string;
  limit?: number;
  offset?: number;
}

export function useFindings(filters?: FindingsFilter) {
  return useQuery({
    queryKey: ["findings", filters],
    queryFn: () => getFindings(filters),
    staleTime: 30_000,
    retry: 2,
  });
}

export function useFinding(findingId: string | null | undefined) {
  return useQuery({
    queryKey: ["finding", findingId],
    queryFn: () => getFinding(findingId!),
    enabled: !!findingId,
    staleTime: 60_000,
    retry: 2,
  });
}

export function useUpdateFindingStatus() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      findingId,
      status,
    }: {
      findingId: string;
      status: Finding["status"];
    }) => updateFindingStatus(findingId, status),
    onSuccess: (_data, { findingId }) => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["finding", findingId] });
    },
  });
}
