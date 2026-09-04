"use client";

import { useState } from "react";
import { X } from "lucide-react";

interface NewScanModalProps {
    open: boolean;
    onClose: () => void;
    onSubmit: (data: {
        repository: string;
        scanType: string;
        targetType: string;
        aiModel: string;
    }) => Promise<void> | void;
}

export function NewScanModal({
    open,
    onClose,
    onSubmit,
}: NewScanModalProps) {

    const [repository, setRepository] =
        useState("");

    const [isSubmitting, setIsSubmitting] =
        useState(false);

    const [targetType, setTargetType] =
        useState("repository");

    const [scanType, setScanType] =
        useState("Full Scan");

    const [aiModel, setAiModel] =
        useState("Security Analyzer");

    async function handleSubmit() {

        if (!repository.trim()) return;

        if (isSubmitting) return;

        try {

            setIsSubmitting(true);

            await onSubmit({
                repository,
                scanType,
                targetType,
                aiModel,
            });

            setRepository("");
            setScanType("Full Scan");
            setTargetType("repository");
            setAiModel("Security Analyzer");

            onClose();

        } finally {

            setIsSubmitting(false);

        }

    }

    if (!open) return null;

    return (

        <div
            className="
            fixed
            inset-0
            z-50
            flex
            items-center
            justify-center
            bg-black/80
            backdrop-blur-sm
            "
        >

            <div
                className="
                w-full
                max-w-2xl
                rounded-2xl
                border
                border-zinc-800
                bg-zinc-950
                p-6
                shadow-2xl
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

                        <h2
                            className="
                            text-xl
                            font-semibold
                            text-zinc-100
                            "
                        >
                            Start Security Scan
                        </h2>

                        <p
                            className="
                            mt-1
                            text-sm
                            text-zinc-400
                            "
                        >
                            Configure scan target and analysis settings
                        </p>

                    </div>


                    <button
                        onClick={onClose}
                        className="
                        rounded-lg
                        p-2
                        hover:bg-zinc-900
                        "
                    >
                        <X
                            size={18}
                            className="text-zinc-400"
                        />
                    </button>

                </div>


                {/* Form */}

                <div
                    className="
                    mt-8
                    space-y-5
                    "
                >

                    <div>

                        <label
                            className="
                            mb-2
                            block
                            text-sm
                            text-zinc-300
                            "
                        >
                            Target Type
                        </label>

                        <select
                            value={targetType}
                            onChange={(e)=>
                                setTargetType(
                                    e.target.value
                                )
                            }
                            className="
                            w-full
                            rounded-lg
                            border
                            border-zinc-800
                            bg-black
                            px-4
                            py-3
                            "
                        >
                            <option value="repository">
                                GitHub Repository
                            </option>

                            <option value="website">
                                Website URL
                            </option>

                            <option value="api">
                                API Endpoint
                            </option>

                            <option value="ai-model">
                                AI Model Testing
                            </option>

                        </select>

                    </div>


                    <div>

                        <label
                            className="
                            mb-2
                            block
                            text-sm
                            text-zinc-300
                            "
                        >
                            Target
                        </label>

                        <input
                            value={repository}
                            onChange={(e)=>
                                setRepository(
                                    e.target.value
                                )
                            }
                            placeholder={
                                targetType==="repository"
                                ? "https://github.com/repo"
                                : targetType==="website"
                                ? "https://example.com"
                                : targetType==="api"
                                ? "https://api.example.com"
                                : "Model name"
                            }
                            className="
                            w-full
                            rounded-lg
                            border
                            border-zinc-800
                            bg-black
                            px-4
                            py-3
                            outline-none
                            focus:border-red-500
                            "
                        />

                    </div>


                    <div>

                        <label
                            className="
                            mb-2
                            block
                            text-sm
                            text-zinc-300
                            "
                        >
                            Scan Type
                        </label>

                        <select
                            value={scanType}
                            onChange={(e)=>
                                setScanType(
                                    e.target.value
                                )
                            }
                            className="
                            w-full
                            rounded-lg
                            border
                            border-zinc-800
                            bg-black
                            px-4
                            py-3
                            "
                        >

                            <option>
                                Full Scan
                            </option>

                            <option>
                                Static Analysis
                            </option>

                            <option>
                                Dependency Analysis
                            </option>

                            <option>
                                AI Analysis
                            </option>

                        </select>

                    </div>


                    <div>

                        <label
                            className="
                            mb-2
                            block
                            text-sm
                            text-zinc-300
                            "
                        >
                            AI Model
                        </label>

                        <select
                            value={aiModel}
                            onChange={(e)=>
                                setAiModel(
                                    e.target.value
                                )
                            }
                            className="
                            w-full
                            rounded-lg
                            border
                            border-zinc-800
                            bg-black
                            px-4
                            py-3
                            "
                        >

                            <option>
                                Security Analyzer
                            </option>

                            <option>
                                NVIDIA Nemotron
                            </option>

                            <option>
                                Llama
                            </option>

                            <option>
                                DeepSeek
                            </option>

                        </select>

                    </div>

                </div>


                {/* Footer */}

                <div
                    className="
                    mt-8
                    flex
                    justify-end
                    gap-3
                    "
                >

                    <button
                        onClick={onClose}
                        className="
                        rounded-lg
                        border
                        border-zinc-800
                        px-5
                        py-3
                        hover:bg-zinc-900
                        "
                    >
                        Cancel
                    </button>

                    <button
                        onClick={handleSubmit}
                        disabled={isSubmitting}
                        className={
                            `
                        rounded-lg
                        bg-red-600
                        px-5
                        py-3
                        font-medium
                        text-white
                        hover:bg-red-700
                        ${isSubmitting ? 'opacity-60 pointer-events-none' : ''}
                        `
                        }
                    >
                        {isSubmitting ? "Starting..." : "Start Scan"}
                    </button>

                </div>

            </div>

        </div>

    );

}
