"use client";

import { Play } from "lucide-react";

import {
    Repository
} from "@/services/repositories.service";

interface RepositoryCardProps
    extends Repository {

    onScan: (
        id: string
    ) => void;

    onView: (
        id: string
    ) => void;

}

function statusStyles(
    status:
    Repository["status"]
) {

    switch (status) {

        case "active":

            return `
            bg-green-500/15
            text-green-400
            `;

        case "inactive":

            return `
            bg-red-500/15
            text-red-400
            `;

        default:

            return `
            bg-zinc-500/15
            text-zinc-400
            `;

    }

}

export function RepositoryCard({

    id,
    name,
    provider,
    status,
    url,
    last_scan,

    onScan,
    onView

}: RepositoryCardProps) {

    return (

        <div
            className="
            rounded-xl
            border
            border-zinc-800
            bg-zinc-950
            p-6
            space-y-5
            "
        >

            <div
                className="
                flex
                items-start
                justify-between
                "
            >

                <div>

                    <h2
                        className="
                        text-xl
                        font-semibold
                        "
                    >
                        {name}
                    </h2>

                    <p
                        className="
                        mt-1
                        text-sm
                        text-zinc-400
                        "
                    >
                        {provider}
                    </p>

                </div>


                <div
                    className={`
                    rounded-full
                    px-3
                    py-1
                    text-xs
                    font-medium
                    ${statusStyles(
                        status
                    )}
                    `}
                >
                    {status === "active" ? "CONNECTED" : "DISCONNECTED"}
                </div>

            </div>


            <div
                className="
                space-y-2
                text-sm
                "
            >

                <div>

                    <p className="text-zinc-500">
                        Repository URL
                    </p>

                    <p
                        className="
                        truncate
                        text-zinc-300
                        "
                    >
                        {url}
                    </p>

                </div>


                <div>

                    <p className="text-zinc-500">
                        Last Scan
                    </p>

                    <p>
                        {last_scan ?? "-"}
                    </p>

                </div>

            </div>


            <div
                className="
                flex
                gap-3
                "
            >

                <button
                    onClick={() =>
                        onScan(id)
                    }
                    className="
                    flex-1
                    rounded-lg
                    bg-red-600
                    px-4
                    py-2
                    text-white
                    hover:bg-red-700
                    flex
                    items-center
                    justify-center
                    gap-2
                    "
                >

                    <Play
                        size={16}
                    />

                    Scan

                </button>


                <button
                    onClick={() =>
                        onView(id)
                    }
                    className="
                    flex-1
                    rounded-lg
                    bg-zinc-900
                    px-4
                    py-2
                    hover:bg-zinc-800
                    "
                >
                    View
                </button>

            </div>

        </div>

    );

}