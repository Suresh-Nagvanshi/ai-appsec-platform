"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Plus } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";

import { ScanCard } from "@/components/scans/scan-card";
import { NewScanModal } from "@/components/scans/new-scan-modal";
import { useScans } from "@/hooks/use-scans";
import {
    startGithubScan,
    type ScanRecord,
} from "@/services/scans.service";

export default function ScansPage() {

    const router = useRouter();
    const queryClient = useQueryClient();
    const [modalOpen, setModalOpen] = useState(false);
    const [submitError, setSubmitError] = useState<string | null>(null);

    const { data, isLoading, error } = useScans();

    async function handleCreateScan(scanData: {
        repository: string;
        scanType: string;
        targetType: string;
        aiModel: string;
    }) {
        setSubmitError(null);

        try {
            if (scanData.targetType !== "repository") {
                setSubmitError(
                    "Only GitHub Repository scanning is supported in this MVP. Select 'GitHub Repository' as the target type."
                );
                return;
            }

            // Start a real backend scan and get scan_id immediately
            const scanId = await startGithubScan(scanData.repository);

            // Optimistically add a QUEUED placeholder card to the list
            const placeholder: ScanRecord = {
                id: scanId,
                scanType: "github",
                target: scanData.repository,
                branch: null,
                commit: null,
                status: "QUEUED",
                progress: 0,
                startedAt: new Date().toISOString(),
                completedAt: null,
                duration: null,
                findingsCount: 0,
                criticalCount: 0,
                summary: {},
                logs: [],
                timeline: [],
                failureReason: null,
            };

            queryClient.setQueryData(
                ["scans"],
                (oldData: ScanRecord[] | undefined) => [
                    placeholder,
                    ...(oldData ?? []),
                ]
            );

            // Navigate to the live scan session page
            router.push(`/scans/${scanId}`);

        } catch (err: unknown) {
            const message =
                err instanceof Error ? err.message : "Scan could not be started";
            setSubmitError(message);
            console.error("Scan creation failed:", err);
        }
    }


    if (isLoading) {
        return (
            <div className="flex items-center gap-3 text-zinc-400 p-6">
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-zinc-400" />
                Loading scans…
            </div>
        );
    }

    if (error) {
        return (
            <div className="rounded-xl border border-red-500/20 bg-zinc-950 p-6 text-red-400">
                <p className="font-semibold">Failed to load scans</p>
                <p className="text-sm mt-1 text-red-300">
                    {error instanceof Error ? error.message : "Unknown error"}
                </p>
                <p className="text-xs mt-2 text-zinc-500">
                    Make sure the backend is running on{" "}
                    <code>{process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"}</code>
                </p>
            </div>
        );
    }

    const scans = data ?? [];

    return (
        <div className="space-y-8">

            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold">Scans</h1>
                    <p className="mt-2 text-zinc-400">
                        Monitor repository security scans
                    </p>
                </div>

                <button
                    onClick={() => {
                        setSubmitError(null);
                        setModalOpen(true);
                    }}
                    className="flex items-center gap-2 rounded-lg bg-red-600 px-5 py-3 font-medium text-white hover:bg-red-700"
                >
                    <Plus size={18} />
                    New Scan
                </button>
            </div>

            {/* Submit error banner */}
            {submitError && (
                <div className="rounded-lg border border-red-500/30 bg-red-950/40 px-4 py-3 text-sm text-red-400">
                    {submitError}
                </div>
            )}

            {/* Empty state */}
            {scans.length === 0 && (
                <div className="flex flex-col items-center justify-center rounded-xl border border-zinc-800 bg-zinc-950 py-20 text-center">
                    <p className="text-zinc-400 text-sm">No scans yet.</p>
                    <p className="text-zinc-600 text-xs mt-1">
                        Click <span className="text-zinc-400">New Scan</span> to start your first scan.
                    </p>
                </div>
            )}

            {/* Scan Grid */}
            <div className="grid gap-6 lg:grid-cols-2 xl:grid-cols-3">
                {scans.map((scan) => (
                    <ScanCard
                        key={scan.id}
                        {...scan}
                        onView={(id) => router.push(`/scans/${id}`)}
                    />
                ))}
            </div>

            <NewScanModal
                open={modalOpen}
                onClose={() => setModalOpen(false)}
                onSubmit={handleCreateScan}
            />

        </div>
    );
}
