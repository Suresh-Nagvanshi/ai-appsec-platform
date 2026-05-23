"use client";

import { useState } from "react";
import { Plus } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";

import { RepositoryCard } from "@/components/repositories/repository-card";
import { AddRepositoryModal } from "@/components/repositories/add-repository-modal";

import { useRepositories } from "@/hooks/use-repositories";

import {
    addRepository,
    type Repository,
} from "@/services/repositories.service";
import { Scan, startScan } from "@/services/scans.service";

export default function RepositoriesPage() {

    const router =
        useRouter();

    const queryClient =
        useQueryClient();

    const [modalOpen, setModalOpen] =
        useState(false);

    const {
        data,
        isLoading,
        error,
    } = useRepositories();


    async function handleAddRepository(
        repositoryData: {
            name: string;
            provider:
            | "GitHub"
            | "GitLab"
            | "Bitbucket";

            url: string;
        }
    ) {

        try {

            const newRepository =
                await addRepository({

                    ...repositoryData,

                    status:
                        "CONNECTED",

                    lastScan:
                        "Never"

                });

            queryClient.setQueryData(

                ["repositories"],

                (
                    oldData:
                    Repository[]
                    | undefined
                ) => [

                        newRepository,
                        ...(oldData ?? [])

                    ]

            );

        }

        catch (error) {

            console.error(
                "Repository creation failed:",
                error
            );

        }

    }


    if (isLoading) {

        return (

            <div
                className="
                text-zinc-400
                "
            >
                Loading repositories...
            </div>

        );

    }


    if (error) {

        return (

            <div
                className="
                rounded-xl
                border
                border-red-500/20
                bg-zinc-950
                p-6
                text-red-400
                "
            >
                Failed to load repositories
            </div>

        );

    }


    const repositories =
        data ?? [];


    return (

        <div
            className="
            space-y-8
            "
        >

            {/* Header */}

            <div
                className="
                flex
                items-center
                justify-between
                "
            >

                <div>

                    <h1
                        className="
                        text-3xl
                        font-bold
                        "
                    >
                        Repositories
                    </h1>

                    <p
                        className="
                        mt-2
                        text-zinc-400
                        "
                    >
                        Manage repositories connected to security scans
                    </p>

                </div>


                <button
                    onClick={() =>
                        setModalOpen(
                            true
                        )
                    }
                    className="
                    flex
                    items-center
                    gap-2
                    rounded-lg
                    bg-red-600
                    px-5
                    py-3
                    font-medium
                    text-white
                    hover:bg-red-700
                    "
                >

                    <Plus
                        size={18}
                    />

                    Add Repository

                </button>

            </div>


            {/* Repository Grid */}

            <div
                className="
                grid
                gap-6
                lg:grid-cols-2
                xl:grid-cols-3
                "
            >

                {
                    repositories.map(
                        (
                            repository
                        ) => (

                            <RepositoryCard

                                key={
                                    repository.id
                                }

                                {...repository}

                                onScan={async (id) => {

    try {

        const repository =
            repositories.find(
                (repo) =>
                    repo.id === id
            );

        if (!repository) {
            return;
        }

        const newScan =
            await startScan({

                repository:
                    repository.name,

                scanType:
                    "Full Scan"

            });

        queryClient.setQueryData(

            ["scans"],

            (
                oldScans:
                Scan[] | undefined
            ) => [

                newScan,
                ...(oldScans ?? [])

            ]

        );

        router.push(
            `/scans/${newScan.id}`
        );

    }

    catch (error) {

        console.error(
            "Failed to start scan:",
            error
        );

    }

}}

                                onView={(
                                    id
                                ) => {

                                    console.log(
                                        "Repository:",
                                        id
                                    );

                                }}

                            />

                        )
                    )
                }

            </div>


            <AddRepositoryModal

                open={
                    modalOpen
                }

                onClose={() =>
                    setModalOpen(
                        false
                    )
                }

                onSubmit={
                    handleAddRepository
                }

            />

        </div>

    );

}