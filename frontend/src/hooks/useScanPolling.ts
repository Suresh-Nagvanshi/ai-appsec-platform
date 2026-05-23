/**
 * useScanPolling
 * ==============
 * React Query hook that polls GET /api/scans/{scanId} every 2 seconds
 * while the scan is in QUEUED or RUNNING state, then stops.
 *
 * Usage:
 *   const { data: scan, isLoading, error } = useScanPolling(scanId);
 */

import { useQuery } from "@tanstack/react-query";
import { getScan, ScanRecord } from "@/services/scans.service";

const POLL_INTERVAL_MS = 2000;
const TERMINAL_STATUSES = new Set(["COMPLETED", "FAILED"]);

export function useScanPolling(scanId: string | null | undefined) {
  return useQuery<ScanRecord, Error>({
    queryKey: ["scan", scanId],
    queryFn: () => getScan(scanId!),
    enabled: !!scanId,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      if (!status || TERMINAL_STATUSES.has(status)) return false;
      return POLL_INTERVAL_MS;
    },
    retry: 3,
  });
}
