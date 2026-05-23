"use client";

import { useQuery } from "@tanstack/react-query";

import {
    getScans,
    type Scan,
} from "@/services/scans.service";

export function useScans() {

    return useQuery<Scan[]>({

        queryKey: [
            "scans"
        ],

        queryFn: getScans,

        staleTime: 1000 * 60 * 5,

        retry: 1,

        refetchOnWindowFocus: false,

    });

}