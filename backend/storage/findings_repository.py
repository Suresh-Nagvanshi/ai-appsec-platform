import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class FindingsRepository:
    """
    Persistent storage layer for security findings.

    Responsibilities:
    - persist findings
    - persist AI analyses
    - historical tracking
    - future diff scanning
    - future dashboard support
    - future RAG memory support

    Storage strategy:
    JSON-based repository storage.
    """

    def __init__(self):

        self.base_path = (
            Path(__file__)
            .resolve()
            .parent
            .parent
            / "database"
        )

        self.findings_path = (
            self.base_path
            / "findings"
        )

        self.scans_path = (
            self.base_path
            / "scans"
        )

        self._initialize_storage()

    def save_scan(
        self,
        project_name: str,
        scan_results: Dict
    ) -> str:
        """
        Save complete scan results.

        Returns:
            scan_id
        """

        scan_id = self._generate_scan_id(
            project_name
        )

        scan_record = {

            "scan_id": scan_id,

            "project_name": project_name,

            "created_at": datetime.utcnow()
            .isoformat(),

            "metadata": scan_results.get(
                "metadata",
                {}
            ),

            "summary": scan_results.get(
                "summary",
                {}
            ),

            "results": scan_results.get(
                "results",
                []
            )
        }

        scan_file = (
            self.scans_path
            / f"{scan_id}.json"
        )

        with open(
            scan_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                scan_record,
                file,
                indent=4
            )

        self._store_individual_findings(
            scan_id=scan_id,
            project_name=project_name,
            results=scan_results.get(
                "results",
                []
            )
        )

        return scan_id

    def get_scan(
        self,
        scan_id: str
    ) -> Optional[Dict]:
        """
        Retrieve scan by ID.
        """

        scan_file = (
            self.scans_path
            / f"{scan_id}.json"
        )

        if not scan_file.exists():
            return None

        with open(
            scan_file,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    def list_scans(
        self
    ) -> List[Dict]:
        """
        List all stored scans.
        """

        scans = []

        for scan_file in self.scans_path.glob(
            "*.json"
        ):

            try:

                with open(
                    scan_file,
                    "r",
                    encoding="utf-8"
                ) as file:

                    data = json.load(file)

                    scans.append({

                        "scan_id": data.get(
                            "scan_id"
                        ),

                        "project_name": data.get(
                            "project_name"
                        ),

                        "created_at": data.get(
                            "created_at"
                        ),

                        "summary": data.get(
                            "summary",
                            {}
                        )
                    })

            except Exception:
                continue

        scans.sort(
            key=lambda item: item.get(
                "created_at",
                ""
            ),
            reverse=True
        )

        return scans

    def get_project_history(
        self,
        project_name: str
    ) -> List[Dict]:
        """
        Retrieve scan history for project.
        """

        history = []

        for scan in self.list_scans():

            if (
                scan.get(
                    "project_name"
                )
                == project_name
            ):
                history.append(scan)

        return history

    def _store_individual_findings(
        self,
        scan_id: str,
        project_name: str,
        results: List[Dict]
    ):
        """
        Store findings individually
        for future querying/RAG.
        """

        for index, finding in enumerate(results):

            record = {

                "finding_id":
                    f"{scan_id}_{index}",

                "scan_id": scan_id,

                "project_name":
                    project_name,

                "created_at":
                    datetime.utcnow()
                    .isoformat(),

                "finding": finding
            }

            finding_file = (
                self.findings_path
                / f"{scan_id}_{index}.json"
            )

            with open(
                finding_file,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    record,
                    file,
                    indent=4
                )

    def _initialize_storage(
        self
    ):
        """
        Initialize repository directories.
        """

        os.makedirs(
            self.base_path,
            exist_ok=True
        )

        os.makedirs(
            self.findings_path,
            exist_ok=True
        )

        os.makedirs(
            self.scans_path,
            exist_ok=True
        )

    @staticmethod
    def _generate_scan_id(
        project_name: str
    ) -> str:
        """
        Generate unique scan ID.
        """

        timestamp = datetime.utcnow().strftime(
            "%Y%m%d_%H%M%S"
        )

        normalized = (
            project_name
            .replace(" ", "_")
            .lower()
        )

        return f"{normalized}_{timestamp}"