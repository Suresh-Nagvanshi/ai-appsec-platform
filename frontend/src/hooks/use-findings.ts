"use client";

import { useQuery } from "@tanstack/react-query";

import { getFindings } from "@/services/findings.service";

export function useFindings() {

    return useQuery({
        queryKey: ["findings"],

        queryFn: getFindings,

    });
}
