"use client";

import { useQuery } from "@tanstack/react-query";

import {
  getScanDetails,
  type ScanDetails
} from "@/services/scan-details.service";

export function useScanDetails(
  scanId: string
) {

  return useQuery<ScanDetails>({

    queryKey: [
      "scan-details",
      scanId
    ],

    queryFn: () =>
      getScanDetails(scanId),

    enabled: !!scanId,

    refetchInterval: 3000

  });

}