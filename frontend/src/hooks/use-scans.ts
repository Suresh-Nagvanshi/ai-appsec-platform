"use client";

import { useQuery } from "@tanstack/react-query";
import { listScans, type ScanRecord } from "@/services/scans.service";

/**
 * useScans
 * ========
 * Returns all scan records, newest first.
 * Re-exported as a convenience wrapper around React Query.
 *
 * Fix: renamed getScans -> listScans to match the updated scans.service.ts
 *      and Scan -> ScanRecord (the canonical type from the service).
 */
export function useScans() {
  return useQuery<ScanRecord[]>({
    queryKey: ["scans"],
    queryFn: listScans,
    staleTime: 1000 * 60 * 5,
    retry: 1,
    refetchOnWindowFocus: false,
  });
}
