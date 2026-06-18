/**
 * use-report hook
 * ===============
 * Wraps generateReport() in a React Query useMutation.
 * Also exports useScansForPicker — a lightweight query that fetches
 * all completed scans to populate the scan_id selector.
 */

"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { generateReport, type Report } from "@/services/reports.service";
import { listScans, type ScanRecord } from "@/services/scans.service";

/**
 * Mutation: call generateReport(scanId) and receive a Report.
 * Usage:
 *   const { mutate, data, isPending, isError, error } = useGenerateReport();
 *   mutate(scanId);
 */
export function useGenerateReport() {
  return useMutation<Report, Error, string>({
    mutationFn: (scanId: string) => generateReport(scanId),
  });
}

/**
 * Query: fetch all scans for the scan picker dropdown.
 * Only COMPLETED scans can have a report generated.
 */
export function useScansForPicker() {
  return useQuery<ScanRecord[]>({
    queryKey: ["scans", "all"],
    queryFn: listScans,
    staleTime: 30_000,
  });
}
