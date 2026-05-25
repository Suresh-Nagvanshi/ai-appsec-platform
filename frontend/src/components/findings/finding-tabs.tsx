// frontend/src/components/findings/finding-tabs.tsx
"use client"

import * as React from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import type { Finding } from "@/types/finding"

interface Props {
  data: Finding & {
    ai_summary?: string
    attack_scenario?: string
    business_impact?: string
    cwe?: string
    owasp?: string
    mitre?: string
    snippet?: string
    code_snippet?: string
    secure_fix?: string
    developer_steps?: string[]
    framework?: string
  }
}

function Pill({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-1 text-xs text-zinc-400">
      {children}
    </span>
  )
}

export function FindingTabs({ data }: Props) {
  return (
    <div className="w-full space-y-4">
      {/* Compact workspace header (keeps existing page theme) */}
      <div className="space-y-2">
        <div className="text-lg font-semibold text-zinc-100">
          {data?.title ?? "SQL Injection vulnerability"}
        </div>
        <div className="flex flex-wrap gap-2">
          <Pill>
            <span className="text-red-500">{data?.severity ?? "Critical"}</span>
          </Pill>
          <Pill>
            Risk{" "}
            <span className="text-zinc-100">{data?.riskScore ?? "9.8"}</span>
          </Pill>
          <Pill>{data?.cwe ?? "CWE-89"}</Pill>
          <Pill>{data?.owasp ?? "OWASP A03"}</Pill>
          <Pill>
            MITRE: {data?.mitre ?? "T1190"}
          </Pill>
        </div>
      </div>

      <Tabs defaultValue="analysis" className="w-full">
        {/* VSCode/browser-like horizontal tabs */}
        <TabsList className="w-full justify-start gap-1 overflow-x-auto rounded-md border border-zinc-800 bg-zinc-950 p-1">
          <TabsTrigger
            value="analysis"
            className="h-8 shrink-0 rounded-md px-3 text-sm text-zinc-400 data-[state=active]:bg-zinc-800 data-[state=active]:text-white data-[state=active]:shadow-none"
          >
            AI Analysis
          </TabsTrigger>
          <TabsTrigger
            value="code"
            className="h-8 shrink-0 rounded-md px-3 text-sm text-zinc-400 data-[state=active]:bg-zinc-800 data-[state=active]:text-white data-[state=active]:shadow-none"
          >
            Code
          </TabsTrigger>
          <TabsTrigger
            value="remediation"
            className="h-8 shrink-0 rounded-md px-3 text-sm text-zinc-400 data-[state=active]:bg-zinc-800 data-[state=active]:text-white data-[state=active]:shadow-none"
          >
            Remediation
          </TabsTrigger>
          <TabsTrigger
            value="timeline"
            className="h-8 shrink-0 rounded-md px-3 text-sm text-zinc-400 data-[state=active]:bg-zinc-800 data-[state=active]:text-white data-[state=active]:shadow-none"
          >
            Timeline
          </TabsTrigger>
        </TabsList>

        <TabsContent value="analysis" className="mt-4">
          <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6">
            <div className="space-y-6 text-zinc-100">
              <section className="space-y-1">
                <div className="text-sm text-zinc-400">Summary</div>
                <div className="text-sm leading-6">{data?.representative_finding?.ai_analysis?.summary ?? "-"}</div>
              </section>
              <section className="space-y-1">
                <div className="text-sm text-zinc-400">Attack Scenario</div>
                <div className="text-sm leading-6">
                  {data?.representative_finding?.ai_analysis?.attack_scenario ?? "-"}
                </div>
              </section>
              <section className="space-y-1">
                <div className="text-sm text-zinc-400">Business Impact</div>
                <div className="text-sm leading-6">
                  {data?.representative_finding?.ai_analysis?.business_impact ?? "-"}
                </div>
              </section>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="code" className="mt-4">
          <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6">
            <div className="mb-4 grid gap-4 md:grid-cols-2">
              <div>
                <div className="text-sm text-zinc-400">Repository</div>
                <div className="text-sm text-zinc-100">
                  {data?.repository ?? "-"}
                </div>
              </div>
              <div>
                <div className="text-sm text-zinc-400">Framework</div>
                <div className="text-sm text-zinc-100">
                  {data?.representative_finding?.framework?.primary_framework ?? "-"}
                </div>
              </div>
            </div>

            <div className="text-sm text-zinc-400">Vulnerable snippet</div>
            <pre className="mt-2 max-h-[420px] overflow-auto rounded-lg border border-zinc-800 bg-black p-4 text-sm text-zinc-100">
              <code className="font-mono">
                {data?.representative_finding?.snippet?.vulnerable_line ?? "-"}
              </code>
            </pre>
          </div>
        </TabsContent>

        <TabsContent value="remediation" className="mt-4">
          <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6">
            <div className="space-y-6">
              <section className="space-y-1">
                <div className="text-sm text-zinc-400">Secure fix</div>
                <div className="text-sm leading-6 text-zinc-100">
                  {data?.representative_finding?.ai_analysis?.secure_fix ?? "-"}
                </div>
              </section>

              <section className="space-y-2">
                <div className="text-sm text-zinc-400">Developer steps</div>
                <ul className="list-disc space-y-2 pl-5 text-sm text-zinc-100">
                  {(data?.representative_finding?.ai_analysis?.developer_remediation_steps ?? []).map((step: string) => (
                    <li key={step}>{step}</li>
                  ))}
                </ul>
              </section>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="timeline" className="mt-4">
          <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6">
            <div className="space-y-4">
              <div className="border-l border-red-500 pl-4">
                <div className="text-sm text-zinc-100">Finding detected</div>
                <div className="text-sm text-zinc-400">
                  {data?.createdAt ?? "-"}
                </div>
              </div>
              <div className="border-l border-zinc-700 pl-4">
                <div className="text-sm text-zinc-100">Status</div>
                <div className="text-sm text-zinc-400">Under investigation</div>
              </div>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}
