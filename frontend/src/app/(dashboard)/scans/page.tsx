"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Plus } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";

import { ScanCard } from "@/components/scans/scan-card";
import { NewScanModal } from "@/components/scans/new-scan-modal";

import { useScans } from "@/hooks/use-scans";

import {
    startScan,
    type Scan
} from "@/services/scans.service";

export default function ScansPage() {

    const router = useRouter();

    const queryClient =
        useQueryClient();

    const [modalOpen, setModalOpen] =
        useState(false);

    const {
        data,
        isLoading,
        error,
    } = useScans();


    async function handleCreateScan(
        scanData: {
            repository: string;
            scanType: string;
            targetType: string;
            aiModel: string;
        }
    ) {

        try {

            const newScan =
                await startScan({

                    repository:
                        scanData.repository,

                    scanType:
                        scanData.scanType

                });

            queryClient.setQueryData(
                ["scans"],
                (
                    oldData:
                    Scan[] | undefined
                ) => [

                    newScan,
                    ...(oldData ?? [])

                ]
            );

        } catch (err) {

            console.error(
                "Scan creation failed:",
                err
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
                Loading scans...
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
                Failed to load scans
            </div>

        );

    }


    const scans =
        data ?? [];


    return (

        <div className="space-y-8">

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
                        Scans
                    </h1>

                    <p
                        className="
                        mt-2
                        text-zinc-400
                        "
                    >
                        Monitor repository security scans
                    </p>

                </div>


                <button
                    onClick={() =>
                        setModalOpen(true)
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

                    <Plus size={18} />

                    New Scan

                </button>

            </div>


            {/* Scan Grid */}

            <div
                className="
                grid
                gap-6
                lg:grid-cols-2
                xl:grid-cols-3
                "
            >

                {scans.map(
                    (scan) => (

                        <ScanCard
                            key={scan.id}
                            {...scan}

                            onView={(id)=>
                                router.push(
                                    `/scans/${id}`
                                )
                            }

                        />

                    )
                )}

            </div>


            <NewScanModal
                open={modalOpen}
                onClose={() =>
                    setModalOpen(false)
                }
                onSubmit={
                    handleCreateScan
                }
            />

        </div>

    );

}