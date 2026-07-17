from __future__ import annotations

from typing import Any

from mldsa_audit_rules import MLDSAAuditRules
from mlkem_audit_rules import MLKEMAuditRules


class AuditEngine:
    """Scheme-aware auditing engine.

    Add new scheme rule-sets here over time (e.g., ML-KEM, SPHINCS+, etc.).
    """

    def __init__(self, chosen_family: str | None, all_files: list[tuple[str, str]]):
        self.chosen_family = chosen_family
        self.all_files = all_files

    def run(self) -> list[dict[str, Any]]:
        if self.chosen_family == "dilithium":
            return MLDSAAuditRules(self.all_files).run()

        if self.chosen_family == "kyber":
            return MLKEMAuditRules(self.all_files).run()

        # Other schemes can be added later.
        return []
