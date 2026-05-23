"""
Async Analysis Engine
=====================
Runs multiple AnalysisEngine.analyze() calls concurrently using
asyncio.to_thread() (no blocking of the event loop).

Fix applied vs original:
  from ai.analysis_engine import ...  →  from backend.ai.analysis_engine import ...
"""

import asyncio
import time
from typing import Dict, List

from backend.ai.analysis_engine import AnalysisEngine


class AsyncAnalysisEngine:

    MAX_CONCURRENT_TASKS = 5

    def __init__(self):
        self.analysis_engine = AnalysisEngine()
        self.semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_TASKS)

    async def analyze_findings(self, findings: List[Dict]) -> Dict:
        start_time = time.time()

        tasks = [self._safe_analyze(finding) for finding in findings]
        results = await asyncio.gather(*tasks)

        successful = sum(1 for r in results if r.get("success", False))
        failed = len(results) - successful
        duration = round(time.time() - start_time, 2)

        return {
            "metadata": {
                "total_findings": len(findings),
                "successful_analyses": successful,
                "failed_analyses": failed,
                "duration_seconds": duration,
                "max_concurrent_tasks": self.MAX_CONCURRENT_TASKS,
            },
            "results": results,
        }

    async def _safe_analyze(self, finding: Dict) -> Dict:
        async with self.semaphore:
            try:
                result = await asyncio.to_thread(self.analysis_engine.analyze, finding)
                return {"success": True, "analysis": result}
            except Exception as error:
                return {"success": False, "error": str(error)}
