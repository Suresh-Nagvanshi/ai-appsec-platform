"use client";

import { useQuery } from "@tanstack/react-query";

import {
    listRepositories
} from "@/services/repositories.service";

export function useRepositories() {

    return useQuery({

        queryKey: [
            "repositories"
        ],

        queryFn:
            listRepositories,

    });

}