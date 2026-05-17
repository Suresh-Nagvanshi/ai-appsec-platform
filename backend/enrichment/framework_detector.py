from pathlib import Path
from typing import Dict, List, Optional


class FrameworkDetector:
    """
    Enterprise-style framework detection engine.

    Detects:
    - backend frameworks
    - frontend frameworks
    - security frameworks
    - API technologies
    - ORM technologies
    """

    FRAMEWORK_SIGNATURES = {
        "Spring Boot": {
            "type": "backend",
            "signatures": [
                "spring-boot",
                "@springbootapplication",
                "springframework.boot"
            ]
        },

        "Spring Security": {
            "type": "security",
            "signatures": [
                "spring-security",
                "websecurityconfigureradapter",
                "securityfilterchain"
            ]
        },

        "Hibernate": {
            "type": "orm",
            "signatures": [
                "hibernate",
                "@entity",
                "sessionfactory"
            ]
        },

        "Express.js": {
            "type": "backend",
            "signatures": [
                "express",
                "app.get(",
                "router.get("
            ]
        },

        "NestJS": {
            "type": "backend",
            "signatures": [
                "@nestjs",
                "@controller",
                "@injectable"
            ]
        },

        "FastAPI": {
            "type": "backend",
            "signatures": [
                "fastapi",
                "@app.get",
                "@app.post"
            ]
        },

        "Django": {
            "type": "backend",
            "signatures": [
                "django",
                "urls.py",
                "settings.py"
            ]
        },

        "Flask": {
            "type": "backend",
            "signatures": [
                "flask",
                "flask(__name__)"
            ]
        },

        "Laravel": {
            "type": "backend",
            "signatures": [
                "laravel",
                "artisan"
            ]
        },

        "React": {
            "type": "frontend",
            "signatures": [
                "react",
                "react-dom",
                "jsx"
            ]
        },

        "Next.js": {
            "type": "frontend",
            "signatures": [
                "next",
                "next.config",
                "getserversideprops"
            ]
        },

        "Angular": {
            "type": "frontend",
            "signatures": [
                "@angular",
                "ngmodule"
            ]
        },

        "GraphQL": {
            "type": "api",
            "signatures": [
                "graphql",
                "apollo",
                "type query"
            ]
        },

        "JWT": {
            "type": "authentication",
            "signatures": [
                "jwt",
                "jsonwebtoken",
                "jjwt"
            ]
        }
    }

    IMPORTANT_FILES = [
        "pom.xml",
        "build.gradle",
        "package.json",
        "requirements.txt",
        "composer.json",
        "Dockerfile"
    ]

    SOURCE_EXTENSIONS = [
        "*.java",
        "*.js",
        "*.ts",
        "*.py",
        "*.jsx",
        "*.tsx"
    ]

    MAX_SOURCE_FILES = 25
    MAX_FILE_READ_SIZE = 5000

    def detect(self, project_path: str) -> Dict:
        """
        Detect frameworks used in project.

        Returns:
        {
            "primary_framework": str,
            "detected_frameworks": [],
            "confidence": float
        }
        """

        try:
            project = Path(project_path)

            if not project.exists():
                return self._empty_response()

            collected_content = self._collect_project_content(project)

            framework_scores = self._calculate_framework_scores(
                collected_content
            )

            if not framework_scores:
                return self._empty_response()

            sorted_frameworks = sorted(
                framework_scores.items(),
                key=lambda x: x[1],
                reverse=True
            )

            primary_framework = sorted_frameworks[0][0]

            detected_frameworks = []

            for framework, score in sorted_frameworks:

                confidence = round(min(score / 3, 1.0), 2)

                detected_frameworks.append({
                    "name": framework,
                    "type": self.FRAMEWORK_SIGNATURES[framework]["type"],
                    "confidence": confidence
                })

            return {
                "primary_framework": primary_framework,
                "detected_frameworks": detected_frameworks,
                "confidence": detected_frameworks[0]["confidence"]
            }

        except Exception:
            return self._empty_response()

    def _collect_project_content(self, project: Path) -> str:
        """
        Collect lightweight project content for detection.
        """

        collected_content = ""

        # Dependency/config files
        for filename in self.IMPORTANT_FILES:

            target = project / filename

            if target.exists():

                try:
                    with open(
                        target,
                        "r",
                        encoding="utf-8",
                        errors="ignore"
                    ) as file:
                        collected_content += file.read().lower()

                except Exception:
                    continue

        # Source files
        source_files = []

        for extension in self.SOURCE_EXTENSIONS:

            source_files.extend(
                list(project.rglob(extension))[
                    :self.MAX_SOURCE_FILES
                ]
            )

        for source_file in source_files:

            try:
                with open(
                    source_file,
                    "r",
                    encoding="utf-8",
                    errors="ignore"
                ) as file:

                    collected_content += file.read(
                        self.MAX_FILE_READ_SIZE
                    ).lower()

            except Exception:
                continue

        return collected_content

    def _calculate_framework_scores(
        self,
        content: str
    ) -> Dict[str, int]:
        """
        Calculate framework match scores.
        """

        framework_scores = {}

        for framework, metadata in self.FRAMEWORK_SIGNATURES.items():

            score = 0

            for signature in metadata["signatures"]:

                if signature.lower() in content:
                    score += 1

            if score > 0:
                framework_scores[framework] = score

        return framework_scores

    @staticmethod
    def _empty_response() -> Dict:
        """
        Default response.
        """

        return {
            "primary_framework": "Unknown",
            "detected_frameworks": [],
            "confidence": 0.0
        }