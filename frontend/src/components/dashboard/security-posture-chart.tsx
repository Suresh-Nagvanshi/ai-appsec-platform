"use client";

import {
    PieChart,
    Pie,
    Cell,
    ResponsiveContainer,
    Tooltip,
} from "recharts";

const data = [
    {
        name: "Critical",
        value: 12,
        color: "#ef4444",
    },
    {
        name: "High",
        value: 28,
        color: "#f97316",
    },
    {
        name: "Medium",
        value: 46,
        color: "#eab308",
    },
    {
        name: "Low",
        value: 38,
        color: "#3b82f6",
    },
];

export function SecurityPostureChart() {
    return (<div
        className="
     rounded-xl border border-zinc-800
     bg-zinc-950 p-6
   "
    > <div className="mb-6"> <h2 className="text-lg font-semibold">
        Security Posture </h2>

            <p className="text-sm text-zinc-400">
                Findings severity distribution
            </p>
        </div>

        <div className="h-[320px] w-full min-w-0">
            <ResponsiveContainer
                width="100%"
                height={320}
            >
                <PieChart>
                    <Pie
                        data={data}
                        dataKey="value"
                        innerRadius={70}
                        outerRadius={100}
                        paddingAngle={3}
                    >
                        {data.map((entry) => (
                            <Cell
                                key={entry.name}
                                fill={entry.color}
                            />
                        ))}
                    </Pie>

                    <Tooltip />
                </PieChart>
            </ResponsiveContainer>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-3">
            {data.map((item) => (
                <div
                    key={item.name}
                    className="flex items-center gap-2"
                >
                    <div
                        className="h-3 w-3 rounded-full"
                        style={{
                            backgroundColor: item.color,
                        }}
                    />

                    <span className="text-sm text-zinc-300">
                        {item.name}
                    </span>
                </div>
            ))}
        </div>
    </div>

    );
}
