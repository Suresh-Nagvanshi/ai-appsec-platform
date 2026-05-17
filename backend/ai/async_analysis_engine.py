import asyncio
import time
from typing import Dict, List

from ai.analysis_engine import AnalysisEngine


class AsyncAnalysisEngine:
    """
    Parallel AI analysis engine.

    Responsibilities:
    - concurrent AI execution
    - runtime reduction
    - scalable orchestration
    - async-ready architecture

    Future upgrades:
    - queue workers
    - distributed execution
    - model routing
    - fallback providers
    - rate-limit handling
    """

    MAX_CONCURRENT_TASKS = 5

    def __init__(self):

        self.analysis_engine = AnalysisEngine()

        self.semaphore = asyncio.Semaphore(
            self.MAX_CONCURRENT_TASKS
        )

    async def analyze_findings(
        self,
        findings: List[Dict]
    ) -> Dict:
        """
        Analyze findings concurrently.
        """

        start_time = time.time()

        tasks = [

            self._safe_analyze(
                finding
            )

            for finding in findings
        ]

        results = await asyncio.gather(
            *tasks
        )

        successful = len([
            result
            for result in results
            if result.get(
                "success",
                False
            )
        ])

        failed = len(results) - successful

        duration = round(
            time.time() - start_time,
            2
        )

        return {

            "metadata": {
                "total_findings": len(
                    findings
                ),

                "successful_analyses": successful,

                "failed_analyses": failed,

                "duration_seconds": duration,

                "max_concurrent_tasks":
                    self.MAX_CONCURRENT_TASKS
            },

            "results": results
        }

    async def _safe_analyze(
        self,
        finding: Dict
    ) -> Dict:
        """
        Safe concurrent analysis wrapper.
        """

        async with self.semaphore:

            try:

                result = await asyncio.to_thread(
                    self.analysis_engine.analyze,
                    finding
                )

                return {
                    "success": True,
                    "analysis": result
                }

            except Exception as error:

                return {
                    "success": False,
                    "error": str(error)
                }