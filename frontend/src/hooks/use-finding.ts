"use client";

import { useQuery } from "@tanstack/react-query";
import { getFindingById } from "@/services/finding-details.service";

export function useFinding(
    id: string
) {
    return useQuery({
        queryKey: [
            "finding",
            id
        ],

        queryFn: () =>
            getFindingById(id),

        enabled: !!id,
    });
}