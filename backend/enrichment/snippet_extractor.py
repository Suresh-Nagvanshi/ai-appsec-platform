from pathlib import Path
from typing import Dict, Optional


class SnippetExtractor:
    """
    Extracts vulnerable code snippets and surrounding context
    from source files.
    """

    def __init__(self, context_lines: int = 5):
        self.context_lines = context_lines

    def extract(
        self,
        file_path: str,
        line_number: int
    ) -> Dict[str, Optional[str]]:
        """
        Extract code snippet and surrounding context.

        Args:
            file_path (str): Absolute or relative file path
            line_number (int): Vulnerable line number

        Returns:
            dict:
                {
                    "vulnerable_line": str,
                    "before_context": str,
                    "after_context": str,
                    "full_context": str
                }
        """

        try:
            path = Path(file_path)

            if not path.exists():
                return self._error_response(
                    f"File not found: {file_path}"
                )

            with open(
                path,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as file:
                lines = file.readlines()

            total_lines = len(lines)

            # Convert to zero-based index
            target_index = line_number - 1

            if target_index < 0 or target_index >= total_lines:
                return self._error_response(
                    f"Invalid line number: {line_number}"
                )

            start = max(0, target_index - self.context_lines)
            end = min(
                total_lines,
                target_index + self.context_lines + 1
            )

            before_context = "".join(
                lines[start:target_index]
            ).rstrip()

            vulnerable_line = lines[target_index].rstrip()

            after_context = "".join(
                lines[target_index + 1:end]
            ).rstrip()

            full_context = "".join(
                lines[start:end]
            ).rstrip()

            return {
                "vulnerable_line": vulnerable_line,
                "before_context": before_context,
                "after_context": after_context,
                "full_context": full_context
            }

        except Exception as error:
            return self._error_response(str(error))

    @staticmethod
    def _error_response(message: str) -> Dict[str, Optional[str]]:
        """
        Standardized error response.
        """

        return {
            "vulnerable_line": None,
            "before_context": None,
            "after_context": None,
            "full_context": None,
            "error": message
        }