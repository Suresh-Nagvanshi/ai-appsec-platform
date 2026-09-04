"use client";

import { useState } from "react";
import { Play, GitBranch, ExternalLink, RefreshCw } from "lucide-react";
import { Repository } from "@/services/repositories.service";

interface RepositoryCardProps extends Repository {
    onScan: (id: string, branch?: string) => void;
    onView: (id: string) => void;
}

function statusStyles(status: Repository["status"]) {
    switch (status) {
        case "active":
            return "bg-green-500/15 text-green-400";
        case "inactive":
            return "bg-red-500/15 text-red-400";
        default:
            return "bg-zinc-500/15 text-zinc-400";
    }
}

export function RepositoryCard({
    id,
    name,
    provider,
    status,
    url,
    last_scan,
    default_branch,
    onScan,
    onView,
}: RepositoryCardProps & { default_branch?: string }) {

    const [scanBranch, setScanBranch] = useState(default_branch ?? "");
    const [showBranchInput, setShowBranchInput] = useState(false);

    return (
        <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6 space-y-5 hover:border-zinc-700 transition-colors">

            {/* Header */}
            <div className="flex items-start justify-between">
                <div className="space-y-1">
                    <h2 className="text-xl font-semibold">{name}</h2>
                    <p className="text-sm text-zinc-400">{provider}</p>
                </div>
                <div className={`rounded-full px-3 py-1 text-xs font-medium ${statusStyles(status)}`}>
                    {status === "active" ? "CONNECTED" : "DISCONNECTED"}
                </div>
            </div>

            {/* Details */}
            <div className="space-y-2 text-sm">
                <div>
                    <p className="text-zinc-500">Repository URL</p>
                    <a
                        href={url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1 truncate text-zinc-300 hover:text-white transition-colors"
                    >
                        <span className="truncate">{url}</span>
                        <ExternalLink size={12} className="shrink-0 text-zinc-500" />
                    </a>
                </div>
                <div className="flex items-center justify-between">
                    <div>
                        <p className="text-zinc-500">Last Scan</p>
                        <p className="text-zinc-300">{last_scan ?? "Never"}</p>
                    </div>
                    {default_branch && (
                        <div className="flex items-center gap-1 rounded-md bg-zinc-900 px-2 py-1">
                            <GitBranch size={12} className="text-zinc-500" />
                            <span className="text-xs text-zinc-400">{default_branch}</span>
                        </div>
                    )}
                </div>
            </div>

            {/* Branch override input */}
            {showBranchInput && (
                <div className="space-y-2">
                    <label className="flex items-center gap-1 text-xs text-zinc-400">
                        <GitBranch size={12} />
                        Scan Branch
                    </label>
                    <input
                        value={scanBranch}
                        onChange={(e) => setScanBranch(e.target.value)}
                        placeholder="main  (leave blank for default)"
                        className="w-full rounded-lg border border-zinc-700 bg-black px-3 py-2 text-sm outline-none focus:border-red-500"
                    />
                </div>
            )}

            {/* Actions */}
            <div className="flex gap-2">
                <button
                    onClick={() => onScan(id, scanBranch.trim() || undefined)}
                    className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-white hover:bg-red-700 transition-colors"
                >
                    <Play size={16} />
                    Scan
                </button>

                <button
                    onClick={() => setShowBranchInput((v) => !v)}
                    title={showBranchInput ? "Hide branch selector" : "Select scan branch"}
                    className={`flex items-center justify-center rounded-lg border px-3 py-2 transition-colors ${
                        showBranchInput
                            ? "border-red-600/40 bg-red-950/30 text-red-400"
                            : "border-zinc-800 bg-zinc-900 hover:bg-zinc-800"
                    }`}
                >
                    <GitBranch size={16} />
                </button>

                <button
                    onClick={() => onView(id)}
                    className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 hover:bg-zinc-800 transition-colors"
                >
                    <ExternalLink size={14} />
                    View
                </button>
            </div>

        </div>
    );
}