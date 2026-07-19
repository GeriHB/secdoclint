"""Regression tests for the repository scanner and core lint rules."""

from pathlib import Path
import tempfile
import unittest

from secdoclint.config import Config
from secdoclint.scanner import scan_repository


class ScannerTests(unittest.TestCase):
    """Verify that representative repository risks produce expected rule IDs."""

    def test_detects_generic_alt_and_broken_link(self) -> None:
        """A missing image with generic alt text should trigger both rules."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(
                "# Test\n\n![alt text](missing.png)\n",
                encoding="utf-8",
            )
            (root / "DISCLAIMER.md").write_text(
                "# Disclaimer\n",
                encoding="utf-8",
            )

            findings = scan_repository(root, Config())
            rule_ids = {finding.rule_id for finding in findings}

            self.assertIn("DOC-MARKDOWN-001", rule_ids)
            self.assertIn("DOC-MARKDOWN-002", rule_ids)

    def test_detects_authorization_header(self) -> None:
        """Bearer credentials inside a code block should still be detected."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(
                "```http\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz\n```\n",
                encoding="utf-8",
            )
            (root / "DISCLAIMER.md").write_text(
                "# Disclaimer\n",
                encoding="utf-8",
            )

            findings = scan_repository(root, Config())
            self.assertTrue(
                any(item.rule_id == "DOC-SECRET-002" for item in findings)
            )

    def test_detects_claim_conflict(self) -> None:
        """Contradictory validation language in one section should be flagged."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(
                "# ESC3\n\nThe path was validated successfully.\n\n"
                "It was not independently tested during this assessment.\n",
                encoding="utf-8",
            )
            (root / "DISCLAIMER.md").write_text(
                "# Disclaimer\n",
                encoding="utf-8",
            )

            findings = scan_repository(root, Config())
            self.assertTrue(
                any(item.rule_id == "DOC-CONSISTENCY-001" for item in findings)
            )


if __name__ == "__main__":
    unittest.main()
