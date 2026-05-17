import {
    AlertTriangle,
    ShieldAlert,
    FolderGit2,
    CheckCircle2,
} from "lucide-react";

const stats = [
    {
        title: "Total Findings",
        value: "124",
        icon: AlertTriangle,
    },
    {
        title: "Critical Findings",
        value: "12",
        icon: ShieldAlert,
    },
    {
        title: "Repositories",
        value: "8",
        icon: FolderGit2,
    },
    {
        title: "Resolved Findings",
        value: "41",
        icon: CheckCircle2,
    },
];

export function StatsCards() {
    return (<div
        className="
     grid gap-4
     md:grid-cols-2
     xl:grid-cols-4
   "
    >
        {stats.map((stat) => {
            const Icon = stat.icon;
            return (
                <div
                    key={stat.title}
                    className="
          rounded-xl border border-zinc-800
          bg-zinc-950 p-6
        "
                >
                    <div className="flex items-start justify-between">
                        <div>
                            <p className="text-sm text-zinc-400">
                                {stat.title}
                            </p>

                            <h2 className="mt-3 text-3xl font-bold">
                                {stat.value}
                            </h2>
                        </div>

                        <div
                            className="
              rounded-lg bg-zinc-900 p-2
            "
                        >
                            <Icon className="h-5 w-5 text-zinc-300" />
                        </div>
                    </div>
                </div>
            );
        })}
    </div>

    );
}
