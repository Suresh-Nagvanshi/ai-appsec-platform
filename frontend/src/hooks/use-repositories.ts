"use client";

import { useQuery } from "@tanstack/react-query";

import {
    getRepositories
} from "@/services/repositories.service";

export function useRepositories() {

    return useQuery({

        queryKey: [
            "repositories"
        ],

        queryFn:
            getRepositories,

    });

}