"use client";

import { useState } from "react";
import { X, GitBranch } from "lucide-react";

interface AddRepositoryModalProps {
    open: boolean;
    onClose: () => void;
    onSubmit: (data: {
        name: string;
        provider: "GitHub" | "GitLab" | "Bitbucket";
        url: string;
        branch?: string;
    }) => Promise<void>;
}

export function AddRepositoryModal({
    open,
    onClose,
    onSubmit,
}: AddRepositoryModalProps) {

    const [isSubmitting, setIsSubmitting] = useState(false);
    const [name, setName] = useState("");
    const [provider, setProvider] = useState<"GitHub" | "GitLab" | "Bitbucket">("GitHub");
    const [url, setUrl] = useState("");
    const [branch, setBranch] = useState("");

    async function handleSubmit() {
        if (isSubmitting || !name.trim() || !url.trim()) return;

        try {
            setIsSubmitting(true);
            await onSubmit({
                name,
                provider,
                url,
                branch: branch.trim() || undefined,
            });
            setName("");
            setProvider("GitHub");
            setUrl("");
            setBranch("");
            onClose();
        } finally {
            setIsSubmitting(false);
        }
    }

    if (!open) return null;

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm"
        >
            <div
                className="w-full max-w-xl rounded-2xl border border-zinc-800 bg-zinc-950 p-6 shadow-xl"
            >
                {/* Header */}
                <div className="flex items-center justify-between">
                    <div>
                        <h2 className="text-xl font-semibold">Add Repository</h2>
                        <p className="mt-1 text-sm text-zinc-400">
                            Connect a repository for security scanning
                        </p>
                    </div>
                    <button
                        onClick={onClose}
                        className="rounded-lg p-2 hover:bg-zinc-900"
                    >
                        <X size={18} className="text-zinc-400" />
                    </button>
                </div>

                {/* Form */}
                <div className="mt-8 space-y-5">

                    {/* Repository Name */}
                    <div>
                        <label className="mb-2 block text-sm text-zinc-300">
                            Repository Name
                        </label>
                        <input
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            placeholder="WebGoat"
                            className="w-full rounded-lg border border-zinc-800 bg-black px-4 py-3 outline-none focus:border-red-500"
                        />
                    </div>

                    {/* Provider */}
                    <div>
                        <label className="mb-2 block text-sm text-zinc-300">
                            Provider
                        </label>
                        <select
                            value={provider}
                            onChange={(e) =>
                                setProvider(e.target.value as "GitHub" | "GitLab" | "Bitbucket")
                            }
                            className="w-full rounded-lg border border-zinc-800 bg-black px-4 py-3"
                        >
                            <option>GitHub</option>
                            <option>GitLab</option>
                            <option>Bitbucket</option>
                        </select>
                    </div>

                    {/* Repository URL */}
                    <div>
                        <label className="mb-2 block text-sm text-zinc-300">
                            Repository URL
                        </label>
                        <input
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            placeholder="https://github.com/org/repo"
                            className="w-full rounded-lg border border-zinc-800 bg-black px-4 py-3 outline-none focus:border-red-500"
                        />
                    </div>

                    {/* Branch */}
                    <div>
                        <label className="mb-2 flex items-center gap-2 text-sm text-zinc-300">
                            <GitBranch size={14} className="text-zinc-500" />
                            Default Scan Branch
                            <span className="text-xs text-zinc-500">(optional)</span>
                        </label>
                        <input
                            value={branch}
                            onChange={(e) => setBranch(e.target.value)}
                            placeholder="main  —  leave blank to use repository default"
                            className="w-full rounded-lg border border-zinc-800 bg-black px-4 py-3 text-sm outline-none focus:border-red-500"
                        />
                        <p className="mt-1 text-xs text-zinc-600">
                            When you scan this repository, this branch will be pre-selected. You can override it per-scan.
                        </p>
                    </div>

                </div>

                {/* Footer */}
                <div className="mt-8 flex justify-end gap-3">
                    <button
                        onClick={onClose}
                        className="rounded-lg border border-zinc-800 px-5 py-3 hover:bg-zinc-900"
                    >
                        Cancel
                    </button>
                    <button
                        disabled={isSubmitting || !name.trim() || !url.trim()}
                        onClick={handleSubmit}
                        className="rounded-lg bg-red-600 px-5 py-3 font-medium text-white disabled:opacity-50 hover:bg-red-700"
                    >
                        {isSubmitting ? "Connecting..." : "Connect Repository"}
                    </button>
                </div>

            </div>
        </div>
    );
}