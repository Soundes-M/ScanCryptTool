from __future__ import annotations

import re
from pathlib import Path
from typing import Any


class MLDSAAuditRules:
    """ML-DSA (Dilithium) specific auditing rules."""

    PARAM_SET_CONSTANTS = {
        "ML-DSA-44": {
            "k": 4,
            "l": 4,
            "eta": 2,
            "tau": 39,
            "beta": 78,
            "gamma1": 1 << 17,
            "gamma2": (8380417 - 1) // 88,
            "omega": 80,
            "lambda": 128,
            "challenge_bytes": 32,
            "public_key_bytes": 1312,
            "private_key_bytes": 2560,
            "signature_bytes": 2420,
        },
        "ML-DSA-65": {
            "k": 6,
            "l": 5,
            "eta": 4,
            "tau": 49,
            "beta": 196,
            "gamma1": 1 << 19,
            "gamma2": (8380417 - 1) // 32,
            "omega": 55,
            "lambda": 192,
            "challenge_bytes": 48,
            "public_key_bytes": 1952,
            "private_key_bytes": 4032,
            "signature_bytes": 3309,
        },
        "ML-DSA-87": {
            "k": 8,
            "l": 7,
            "eta": 2,
            "tau": 60,
            "beta": 120,
            "gamma1": 1 << 19,
            "gamma2": (8380417 - 1) // 32,
            "omega": 75,
            "lambda": 256,
            "challenge_bytes": 64,
            "public_key_bytes": 2592,
            "private_key_bytes": 4896,
            "signature_bytes": 4627,
        },
    }

    PARAM_SYMBOLS = {
        "k": ["K", "DILITHIUM_K", "ML_DSA_K"],
        "l": ["L", "DILITHIUM_L", "ML_DSA_L"],
        "eta": ["ETA", "DILITHIUM_ETA", "ML_DSA_ETA"],
        "tau": ["TAU", "DILITHIUM_TAU", "ML_DSA_TAU"],
        "beta": ["BETA", "DILITHIUM_BETA", "ML_DSA_BETA"],
        "gamma1": ["GAMMA1", "DILITHIUM_GAMMA1", "ML_DSA_GAMMA1"],
        "gamma2": ["GAMMA2", "DILITHIUM_GAMMA2", "ML_DSA_GAMMA2"],
        "omega": ["OMEGA", "DILITHIUM_OMEGA", "ML_DSA_OMEGA"],
        "lambda": ["LAMBDA", "DILITHIUM_LAMBDA", "ML_DSA_LAMBDA"],
        "d": ["D", "DILITHIUM_D", "ML_DSA_D"],
        "challenge_bytes": [
            "CTILDEBYTES",
            "CHALLENGEBYTES",
            "C_TILDE_BYTES",
            "ML_DSA_CHALLENGE_BYTES",
        ],
        "public_key_bytes": ["CRYPTO_PUBLICKEYBYTES", "PUBLICKEYBYTES", "ML_DSA_PUBLICKEYBYTES"],
        "private_key_bytes": ["CRYPTO_SECRETKEYBYTES", "SECRETKEYBYTES", "ML_DSA_SECRETKEYBYTES"],
        "signature_bytes": ["CRYPTO_BYTES", "SIGNBYTES", "SIGNATUREBYTES", "ML_DSA_SIGNATUREBYTES"],
        "seed_bytes": ["SEEDBYTES", "KEYGEN_SEEDBYTES", "ML_DSA_SEEDBYTES"],
    }

    def __init__(self, all_files: list[tuple[str, str]]):
        self.all_files = all_files

    def run(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        findings.append(self.check_fips204_static_001())
        findings.append(self.check_fips204_static_002())
        findings.append(self.check_fips204_static_003())
        findings.append(self.check_fips204_static_004())
        findings.append(self.check_fips204_static_005())
        findings.append(self.check_fips204_static_006())
        findings.append(self.check_fips204_static_007())
        findings.append(self.check_fips204_static_008())
        findings.append(self.check_fips204_static_009())
        findings.append(self.check_fips204_static_010())
        findings.append(self.check_fips204_static_011())
        findings.append(self.check_fips204_static_012())
        findings.append(self.check_fips204_static_013())
        findings.append(self.check_fips204_static_014())
        findings.append(self.check_fips204_static_015())
        findings.append(self.check_fips204_static_016())
        findings.append(self.check_fips204_static_017())
        findings.append(self.check_fips204_static_018())
        findings.append(self.check_fips204_static_019())
        findings.append(self.check_fips204_static_020())
        findings.append(self.check_fips204_static_021())
        findings.append(self.check_fips204_static_022())
        findings.append(self.check_fips204_static_023())
        findings.append(self.check_fips204_static_024())
        findings.append(self.check_fips204_static_025())
        findings.append(self.check_fips204_static_026())
        findings.append(self.check_fips204_static_031())
        findings.append(self.check_fips204_static_032())
        findings.append(self.check_fips204_static_033())
        findings.append(self.check_fips204_static_034())
        findings.append(self.check_fips204_static_035())
        findings.append(self.check_fips204_static_036())
        findings.append(self.check_fips204_static_037())
        findings.append(self.check_fips204_static_038())
        findings.append(self.check_fips204_static_039())
        findings.append(self.check_fips204_static_040())
        findings.append(self.check_fips204_static_041())
        findings.append(self.check_fips204_static_042())
        findings.append(self.check_fips204_static_043())
        findings.append(self.check_fips204_static_044())
        findings.append(self.check_fips204_static_045())
        findings.append(self.check_fips204_static_046())
        findings.append(self.check_fips204_static_047())
        findings.append(self.check_fips204_static_048())
        findings.append(self.check_fips204_static_049())
        findings.append(self.check_fips204_static_050())
        findings.append(self.check_fips204_static_051())
        findings.append(self.check_fips204_static_052())
        findings.append(self.check_fips204_static_053())
        findings.append(self.check_fips204_static_054())
        findings.append(self.check_fips204_static_055())
        findings.append(self.check_fips204_static_056())
        return findings

    @staticmethod
    def _parse_int_literal(expr: str | None) -> int | None:
        if not expr:
            return None
        token = expr.strip()
        m = re.match(r"^([+-]?(?:0[xX][0-9A-Fa-f]+|\d+))(?:[uUlL]+)?$", token)
        if not m:
            return None
        try:
            return int(m.group(1), 0)
        except Exception:
            return None

    @classmethod
    def _evaluate_int_expr(cls, expr: str | None) -> int | None:
        if not expr:
            return None
        token = expr.strip()
        token = token.split("//", 1)[0].strip()

        while token.startswith("(") and token.endswith(")") and len(token) > 2:
            token = token[1:-1].strip()

        literal = cls._parse_int_literal(token)
        if literal is not None:
            return literal

        shift = re.fullmatch(r"\(?\s*(\d+)\s*<<\s*(\d+)\s*\)?", token)
        if shift:
            return int(shift.group(1)) << int(shift.group(2))

        div_with_q = re.fullmatch(
            r"\(?\s*\(?\s*(?:Q|q|DILITHIUM_Q|ML_DSA_Q|8380417)\s*-\s*1\s*\)?\s*\)?\s*/\s*(\d+)\s*",
            token,
        )
        if div_with_q:
            denom = int(div_with_q.group(1))
            return (8380417 - 1) // denom

        return None

    @staticmethod
    def _make_finding(
        rule_id: str,
        title: str,
        status: str,
        severity: str,
        description: str,
        technical_explanation: str,
        impact: str,
        mitigation: str,
        file: str = "-",
        line: int | str = "-",
    ) -> dict[str, Any]:
        return {
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "category": "FIPS 204 / Static",
            "status": status,
            "affected_algorithm": "ML-DSA",
            "file": file,
            "line": line,
            "description": description,
            "impact": impact,
            "technical_explanation": technical_explanation,
            "mitigation": mitigation,
            "references": ["NIST FIPS 204"],
        }

    def _extract_symbol_candidates(self, symbols: list[str]) -> list[tuple[str, int, str, int]]:
        candidates: list[tuple[str, int, str, int]] = []

        for file_path, code in self.all_files:
            for symbol in symbols:
                esc = re.escape(symbol)
                patterns = [
                    rf"^\s*#\s*define\s+{esc}\s+([^\n/]+)",
                    rf"\b(?:const\s+)?(?:static\s+)?(?:unsigned\s+|signed\s+)?(?:short\s+|long\s+)?(?:int|int32_t|uint32_t|int64_t|uint64_t)\s+{esc}\s*=\s*([^;\n]+)",
                ]
                for pattern in patterns:
                    for match in re.finditer(pattern, code, re.MULTILINE):
                        value = self._evaluate_int_expr(match.group(1))
                        if value is None:
                            continue
                        line = code.count("\n", 0, match.start()) + 1
                        candidates.append((file_path, line, symbol, value))

        return candidates

    def _collect_param_values(self) -> dict[str, list[tuple[str, int, str, int]]]:
        values: dict[str, list[tuple[str, int, str, int]]] = {}
        for param_name, symbols in self.PARAM_SYMBOLS.items():
            values[param_name] = self._extract_symbol_candidates(symbols)
        return values

    def _selected_param_set(self, values: dict[str, list[tuple[str, int, str, int]]]) -> str | None:
        k_values = [x[3] for x in values.get("k", [])]
        l_values = [x[3] for x in values.get("l", [])]

        for set_name, req in self.PARAM_SET_CONSTANTS.items():
            if req["k"] in k_values and req["l"] in l_values:
                return set_name

        all_code = "\n".join(code for _, code in self.all_files)
        if re.search(r"ML_DSA_44|DILITHIUM2", all_code, re.IGNORECASE):
            return "ML-DSA-44"
        if re.search(r"ML_DSA_65|DILITHIUM3", all_code, re.IGNORECASE):
            return "ML-DSA-65"
        if re.search(r"ML_DSA_87|DILITHIUM5", all_code, re.IGNORECASE):
            return "ML-DSA-87"

        return None

    def _extract_q_candidates(self) -> list[tuple[str, int, str, int]]:
        return self._extract_symbol_candidates(["Q", "q", "DILITHIUM_Q", "ML_DSA_Q"])

    def _check_object_size_rule(self, set_name: str, rule_id: str) -> dict[str, Any]:
        values = self._collect_param_values()
        selected = self._selected_param_set(values)
        required = self.PARAM_SET_CONSTANTS[set_name]

        if selected and selected != set_name:
            return self._make_finding(
                rule_id=rule_id,
                title=f"{set_name} object sizes are correct",
                status="Not Applicable",
                severity="Information",
                description=f"Rule applies to {set_name}; current implementation appears to target {selected}.",
                technical_explanation=f"Detected parameter set: {selected}.",
                impact="None.",
                mitigation="Run this rule for a build configured to the matching parameter set.",
            )

        missing: list[str] = []
        mismatches: list[str] = []
        anchors: list[tuple[str, int]] = []
        for key in ("public_key_bytes", "private_key_bytes", "signature_bytes"):
            observed = values.get(key, [])
            expected = required[key]
            if not observed:
                missing.append(key)
                continue
            anchors.append((Path(observed[0][0]).name, observed[0][1]))
            observed_values = sorted({v for _, _, _, v in observed})
            if expected not in observed_values:
                mismatches.append(f"{key} expected {expected}, observed {observed_values}")

        if not missing and not mismatches:
            file_name, line = anchors[0] if anchors else ("-", "-")
            return self._make_finding(
                rule_id=rule_id,
                title=f"{set_name} object sizes are correct",
                status="Passed",
                severity="Information",
                description=f"Verified encoded object sizes for {set_name} (pk/sk/sig) match FIPS 204.",
                technical_explanation=(
                    f"public_key_bytes={required['public_key_bytes']}, "
                    f"private_key_bytes={required['private_key_bytes']}, "
                    f"signature_bytes={required['signature_bytes']}"
                ),
                impact="Correct object sizes are required for interoperability and strict decoding.",
                mitigation="Keep exported size constants bound to selected parameter set.",
                file=file_name,
                line=line,
            )

        details = []
        if missing:
            details.append("Missing size constants: " + ", ".join(missing))
        if mismatches:
            details.append("Size mismatches: " + "; ".join(mismatches))

        return self._make_finding(
            rule_id=rule_id,
            title=f"{set_name} object sizes are correct",
            status="Failed",
            severity="High",
            description=f"Encoded public/private key and signature sizes for {set_name} must match FIPS 204.",
            technical_explanation=" ".join(details),
            impact="Wrong object sizes can cause decode failures or non-conformant acceptance behavior.",
            mitigation="Define and export exact pk/sk/sig sizes for the active parameter set.",
        )

    @staticmethod
    def _contains_any(code: str, patterns: list[str]) -> bool:
        return any(re.search(p, code, re.IGNORECASE) for p in patterns)

    def _all_code(self) -> str:
        return "\n".join(code for _, code in self.all_files)

    def check_fips204_static_001(self) -> dict[str, Any]:
        """FIPS204-STATIC-001 — Coefficient modulus is correct (q = 8380417)."""
        expected_q = 8380417
        candidates = self._extract_q_candidates()
        matching = [item for item in candidates if item[3] == expected_q]
        wrong = [item for item in candidates if item[3] != expected_q]

        if matching:
            file_path, line, symbol, value = matching[0]
            return {
                "rule_id": "FIPS204-STATIC-001",
                "title": "Coefficient modulus is correct",
                "severity": "Information",
                "category": "FIPS 204 / Static",
                "status": "Passed",
                "affected_algorithm": "ML-DSA",
                "file": Path(file_path).name,
                "line": line,
                "description": "Static check confirmed the ML-DSA coefficient modulus is defined as q = 8380417 using a recognized modulus symbol (q/Q/DILITHIUM_Q/ML_DSA_Q), which is the required FIPS 204 value for polynomial arithmetic and NTT-domain operations.",
                "impact": "Incorrect modulus breaks ML-DSA arithmetic correctness and interoperability.",
                "technical_explanation": f"Detected {symbol} = {value}.",
                "mitigation": "Keep modulus definitions aligned with FIPS 204 constants.",
                "references": ["NIST FIPS 204"],
            }

        if wrong:
            file_path, line, symbol, value = wrong[0]
            details = f"Detected {symbol} = {value}; expected q = {expected_q}."
            file_name = Path(file_path).name
        else:
            details = "No extractable q/Q/DILITHIUM_Q/ML_DSA_Q definition was found."
            file_name = "-"
            line = "-"

        return {
            "rule_id": "FIPS204-STATIC-001",
            "title": "Coefficient modulus is correct",
            "severity": "High",
            "category": "FIPS 204 / Static",
            "status": "Failed",
            "affected_algorithm": "ML-DSA",
            "file": file_name,
            "line": line,
            "description": "Static check could not validate the required ML-DSA modulus q = 8380417. The analyzer searched for q/Q/DILITHIUM_Q/ML_DSA_Q definitions and either found a different value or no extractable constant. FIPS 204 conformance requires the exact integer value 8380417.",
            "impact": "Wrong or missing modulus can invalidate signatures and conformance claims.",
            "technical_explanation": details,
            "mitigation": "Define q exactly as 8380417 and use it consistently across ML-DSA arithmetic.",
            "references": ["NIST FIPS 204"],
        }

    def check_fips204_static_002(self) -> dict[str, Any]:
        """FIPS204-STATIC-002 — Power2Round parameter is correct (d = 13)."""
        expected_d = 13
        candidates = self._extract_symbol_candidates(self.PARAM_SYMBOLS["d"])
        matching = [item for item in candidates if item[3] == expected_d]
        wrong = [item for item in candidates if item[3] != expected_d]

        if matching:
            file_path, line, symbol, value = matching[0]
            return self._make_finding(
                rule_id="FIPS204-STATIC-002",
                title="Power2Round parameter is correct",
                status="Passed",
                severity="Information",
                description="Verified required Power2Round parameter d = 13.",
                technical_explanation=f"Detected {symbol} = {value}.",
                impact="Wrong d breaks decomposition/rounding behavior and interoperability.",
                mitigation="Keep d fixed to 13 for ML-DSA.",
                file=Path(file_path).name,
                line=line,
            )

        if wrong:
            file_path, line, symbol, value = wrong[0]
            details = f"Detected {symbol} = {value}; expected d = {expected_d}."
            file_name = Path(file_path).name
        else:
            details = "No extractable D/DILITHIUM_D/ML_DSA_D definition was found."
            file_name = "-"
            line = "-"

        return self._make_finding(
            rule_id="FIPS204-STATIC-002",
            title="Power2Round parameter is correct",
            status="Failed",
            severity="High",
            description="Power2Round parameter must be d = 13.",
            technical_explanation=details,
            impact="Incorrect d produces non-conformant key/signature computations.",
            mitigation="Define d exactly as 13 and use it consistently in decomposition logic.",
            file=file_name,
            line=line,
        )

    def _check_param_set_constants(self, set_name: str, rule_id: str) -> dict[str, Any]:
        values = self._collect_param_values()
        selected = self._selected_param_set(values)
        required = self.PARAM_SET_CONSTANTS[set_name]

        if selected and selected != set_name:
            return self._make_finding(
                rule_id=rule_id,
                title=f"{set_name} constants are correct",
                status="Not Applicable",
                severity="Information",
                description=f"Rule applies to {set_name}; selected implementation appears to target {selected}.",
                technical_explanation=f"Detected parameter set: {selected}.",
                impact="None.",
                mitigation="Run this check against a project configured for the matching parameter set.",
            )

        mismatches: list[str] = []
        missing: list[str] = []
        example_file = "-"
        example_line: int | str = "-"

        for key in ("k", "l", "eta", "tau", "beta", "gamma1", "gamma2", "omega", "lambda"):
            found = values.get(key, [])
            expected = required[key]
            if not found:
                missing.append(key)
                continue

            if example_file == "-":
                example_file = Path(found[0][0]).name
                example_line = found[0][1]

            observed_values = sorted({v for _, _, _, v in found})
            if expected not in observed_values:
                mismatches.append(f"{key}: expected {expected}, observed {observed_values}")

        if not mismatches and not missing:
            return self._make_finding(
                rule_id=rule_id,
                title=f"{set_name} constants are correct",
                status="Passed",
                severity="Information",
                description=f"Verified {set_name} constants (k, l, eta, tau, beta, gamma1, gamma2, omega, lambda).",
                technical_explanation="All required constants matched expected values.",
                impact="Consistent constants are required for conformant ML-DSA behavior.",
                mitigation="Keep these constants bound to one parameter set.",
                file=example_file,
                line=example_line,
            )

        details = []
        if mismatches:
            details.append("Mismatches: " + "; ".join(mismatches))
        if missing:
            details.append("Missing constants: " + ", ".join(missing))

        return self._make_finding(
            rule_id=rule_id,
            title=f"{set_name} constants are correct",
            status="Failed",
            severity="High",
            description=f"{set_name} constants must match the FIPS 204 profile.",
            technical_explanation=" ".join(details) if details else "Constants could not be verified.",
            impact="Mixed or wrong constants produce non-conformant keys/signatures.",
            mitigation="Use a single parameter profile and correct any mixed constants.",
            file=example_file,
            line=example_line,
        )

    def check_fips204_static_003(self) -> dict[str, Any]:
        """FIPS204-STATIC-003 — ML-DSA-44 constants are correct."""
        return self._check_param_set_constants("ML-DSA-44", "FIPS204-STATIC-003")

    def check_fips204_static_004(self) -> dict[str, Any]:
        """FIPS204-STATIC-004 — ML-DSA-65 constants are correct."""
        return self._check_param_set_constants("ML-DSA-65", "FIPS204-STATIC-004")

    def check_fips204_static_005(self) -> dict[str, Any]:
        """FIPS204-STATIC-005 — ML-DSA-87 constants are correct."""
        return self._check_param_set_constants("ML-DSA-87", "FIPS204-STATIC-005")

    def check_fips204_static_006(self) -> dict[str, Any]:
        """FIPS204-STATIC-006 — Vector dimensions match k and l (heuristic static checks)."""
        values = self._collect_param_values()
        selected = self._selected_param_set(values)

        if not selected:
            return self._make_finding(
                rule_id="FIPS204-STATIC-006",
                title="Vector dimensions match k and l",
                status="Failed",
                severity="Medium",
                description="Could not verify vector/matrix dimensions without identifying parameter set.",
                technical_explanation="No unambiguous ML-DSA parameter-set selection was found.",
                impact="Dimension mismatches can break matrix/vector arithmetic.",
                mitigation="Expose clear K/L constants or parameter-set identifiers.",
            )

        k = self.PARAM_SET_CONSTANTS[selected]["k"]
        l = self.PARAM_SET_CONSTANTS[selected]["l"]

        reversed_hits: list[str] = []
        hardcoded_mismatch_hits: list[str] = []
        positive_hits = 0

        for file_path, code in self.all_files:
            file_name = Path(file_path).name

            if re.search(r"\[(?:L|l|%d)\]\[(?:K|k|%d)\]" % (l, k), code):
                reversed_hits.append(f"{file_name}: potential [l][k] pattern")

            if re.search(r"\[(?:K|k|%d)\]\[(?:L|l|%d)\]" % (k, l), code):
                positive_hits += 1

            for loop_match in re.finditer(r"for\s*\([^;]*;\s*[^;]*<\s*(\d+)\s*;", code):
                bound = int(loop_match.group(1))
                if bound in {4, 5, 6, 7, 8} and bound not in {k, l}:
                    line = code.count("\n", 0, loop_match.start()) + 1
                    hardcoded_mismatch_hits.append(f"{file_name}:{line} uses loop bound {bound}")

        if not reversed_hits and not hardcoded_mismatch_hits and positive_hits > 0:
            return self._make_finding(
                rule_id="FIPS204-STATIC-006",
                title="Vector dimensions match k and l",
                status="Passed",
                severity="Information",
                description="No obvious dimension mismatch patterns were found for selected k and l.",
                technical_explanation=f"Selected set {selected} uses k={k}, l={l}; no reversed/hard-coded mismatch evidence found.",
                impact="Correct dimensions are required for conformant matrix/vector operations.",
                mitigation="Continue enforcing k/l from a single parameter profile.",
            )

        details = []
        if reversed_hits:
            details.append("Reversed dimension indicators: " + "; ".join(reversed_hits[:3]))
        if hardcoded_mismatch_hits:
            details.append("Hard-coded bounds from another set: " + "; ".join(hardcoded_mismatch_hits[:3]))
        if positive_hits == 0:
            details.append("No strong positive k/l dimension evidence found.")

        return self._make_finding(
            rule_id="FIPS204-STATIC-006",
            title="Vector dimensions match k and l",
            status="Failed",
            severity="High",
            description="Matrix/vector dimensions and loop bounds must consistently match selected k and l.",
            technical_explanation=" ".join(details),
            impact="Dimension errors can invalidate signature/key computations.",
            mitigation="Use symbolic K/L in matrix declarations, vector sizes, allocations, and loops.",
        )

    def check_fips204_static_007(self) -> dict[str, Any]:
        """FIPS204-STATIC-007 — Challenge size matches lambda."""
        values = self._collect_param_values()
        selected = self._selected_param_set(values)
        if not selected:
            return self._make_finding(
                rule_id="FIPS204-STATIC-007",
                title="Challenge size matches lambda",
                status="Failed",
                severity="Medium",
                description="Could not verify challenge size without identifying parameter set.",
                technical_explanation="No unambiguous ML-DSA-44/65/87 selection detected.",
                impact="Wrong challenge size breaks interoperability and verification.",
                mitigation="Make parameter-set selection explicit and expose challenge-size constants.",
            )

        expected = self.PARAM_SET_CONSTANTS[selected]["challenge_bytes"]
        candidates = values.get("challenge_bytes", [])
        matching = [c for c in candidates if c[3] == expected]
        wrong = [c for c in candidates if c[3] != expected]

        if matching:
            file_path, line, symbol, value = matching[0]
            return self._make_finding(
                rule_id="FIPS204-STATIC-007",
                title="Challenge size matches lambda",
                status="Passed",
                severity="Information",
                description=f"Verified challenge length for {selected} is {expected} bytes.",
                technical_explanation=f"Detected {symbol} = {value} bytes.",
                impact="Correct challenge size is required for standardized encoding.",
                mitigation="Keep challenge-byte constants bound to selected lambda.",
                file=Path(file_path).name,
                line=line,
            )

        if wrong:
            file_path, line, symbol, value = wrong[0]
            details = f"Detected {symbol} = {value}; expected {expected} bytes for {selected}."
            file_name = Path(file_path).name
        else:
            details = "No extractable challenge-size constant (e.g., CTILDEBYTES/CHALLENGEBYTES) was found."
            file_name = "-"
            line = "-"

        return self._make_finding(
            rule_id="FIPS204-STATIC-007",
            title="Challenge size matches lambda",
            status="Failed",
            severity="High",
            description=f"Challenge length must be {expected} bytes for {selected}.",
            technical_explanation=details,
            impact="Incorrect challenge length breaks signature encoding and verification compatibility.",
            mitigation="Set challenge bytes to 32/48/64 for ML-DSA-44/65/87 respectively.",
            file=file_name,
            line=line,
        )

    def check_fips204_static_008(self) -> dict[str, Any]:
        """FIPS204-STATIC-012 — ML-DSA-44 object sizes are correct."""
        return self._check_object_size_rule("ML-DSA-44", "FIPS204-STATIC-012")

    def check_fips204_static_009(self) -> dict[str, Any]:
        """FIPS204-STATIC-013 — ML-DSA-65 object sizes are correct."""
        return self._check_object_size_rule("ML-DSA-65", "FIPS204-STATIC-013")

    def check_fips204_static_010(self) -> dict[str, Any]:
        """FIPS204-STATIC-014 — ML-DSA-87 object sizes are correct."""
        return self._check_object_size_rule("ML-DSA-87", "FIPS204-STATIC-014")

    def check_fips204_static_011(self) -> dict[str, Any]:
        """FIPS204-STATIC-015 — API length constants are consistent."""
        values = self._collect_param_values()
        selected = self._selected_param_set(values)
        if not selected:
            return self._make_finding(
                rule_id="FIPS204-STATIC-015",
                title="API length constants are consistent",
                status="Failed",
                severity="Medium",
                description="Could not validate API size consistency without identifying parameter set.",
                technical_explanation="No clear ML-DSA parameter set was detected.",
                impact="Inconsistent API lengths can cause incorrect acceptance/rejection behavior.",
                mitigation="Expose parameter-set markers and size constants clearly.",
            )

        req = self.PARAM_SET_CONSTANTS[selected]
        pv = values.get("public_key_bytes", [])
        sv = values.get("private_key_bytes", [])
        sigv = values.get("signature_bytes", [])
        consistent = any(x[3] == req["public_key_bytes"] for x in pv) and any(x[3] == req["private_key_bytes"] for x in sv) and any(x[3] == req["signature_bytes"] for x in sigv)

        all_code = "\n".join(code for _, code in self.all_files)
        has_api_checks = self._contains_any(
            all_code,
            [
                r"siglen\s*!=\s*(?:CRYPTO_BYTES|SIGNATUREBYTES|ML_DSA_SIGNATUREBYTES|\d+)",
                r"pklen\s*!=\s*(?:CRYPTO_PUBLICKEYBYTES|PUBLICKEYBYTES|ML_DSA_PUBLICKEYBYTES|\d+)",
                r"sklen\s*!=\s*(?:CRYPTO_SECRETKEYBYTES|SECRETKEYBYTES|ML_DSA_SECRETKEYBYTES|\d+)",
            ],
        )

        if consistent and has_api_checks:
            return self._make_finding(
                rule_id="FIPS204-STATIC-015",
                title="API length constants are consistent",
                status="Passed",
                severity="Information",
                description="Exported size constants and API length checks are consistent with the selected parameter set.",
                technical_explanation=f"Detected {selected} size constants and explicit API checks for pk/sk/sig lengths.",
                impact="Consistent API sizes prevent silent truncation/extension acceptance.",
                mitigation="Keep API checks tied to exported constants.",
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-015",
            title="API length constants are consistent",
            status="Failed",
            severity="High",
            description="API constants, buffer declarations, and length checks must consistently use FIPS 204 object sizes.",
            technical_explanation=f"consistent_constants={consistent}, explicit_api_checks={has_api_checks}",
            impact="Inconsistent API length handling can break conformance and robustness.",
            mitigation="Use one set of exported size constants and enforce exact checks in API entry points.",
        )

    def check_fips204_static_012(self) -> dict[str, Any]:
        """FIPS204-STATIC-016 — Exact signature length is checked."""
        all_code = "\n".join(code for _, code in self.all_files)
        exact_check = self._contains_any(
            all_code,
            [
                r"sig(?:len|_len)?\s*!=\s*(?:CRYPTO_BYTES|SIGNATUREBYTES|ML_DSA_SIGNATUREBYTES|\d+)",
                r"if\s*\(\s*[^\)]*sig(?:len|_len)?\s*==\s*(?:CRYPTO_BYTES|SIGNATUREBYTES|ML_DSA_SIGNATUREBYTES|\d+)",
            ],
        )
        weak_checks = self._contains_any(
            all_code,
            [
                r"sig(?:len|_len)?\s*<\s*(?:CRYPTO_BYTES|SIGNATUREBYTES|ML_DSA_SIGNATUREBYTES|\d+)",
                r"sig(?:len|_len)?\s*>=\s*(?:CRYPTO_BYTES|SIGNATUREBYTES|ML_DSA_SIGNATUREBYTES|\d+)",
            ],
        )

        if exact_check and not weak_checks:
            return self._make_finding(
                rule_id="FIPS204-STATIC-016",
                title="Exact signature length is checked",
                status="Passed",
                severity="Information",
                description="Verification path appears to enforce exact signature length.",
                technical_explanation="Detected equality/inequality exact signature-length checks without minimum-only patterns.",
                impact="Exact checks prevent acceptance of truncated or extended signatures.",
                mitigation="Keep strict signature length checks before decode/verify steps.",
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-016",
            title="Exact signature length is checked",
            status="Failed",
            severity="High",
            description="Verification must reject truncated or extended signatures via exact-length checks.",
            technical_explanation=f"exact_check={exact_check}, weak_minimum_or_range_checks={weak_checks}",
            impact="Weak checks can accept malformed signatures or trailing bytes.",
            mitigation="Use exact-length check (== expected) semantics before verification.",
        )

    def check_fips204_static_013(self) -> dict[str, Any]:
        """FIPS204-STATIC-017 — Exact key lengths are checked."""
        all_code = "\n".join(code for _, code in self.all_files)
        pk_exact = self._contains_any(all_code, [r"pk(?:len|_len)?\s*!=\s*(?:CRYPTO_PUBLICKEYBYTES|PUBLICKEYBYTES|ML_DSA_PUBLICKEYBYTES|\d+)"])
        sk_exact = self._contains_any(all_code, [r"sk(?:len|_len)?\s*!=\s*(?:CRYPTO_SECRETKEYBYTES|SECRETKEYBYTES|ML_DSA_SECRETKEYBYTES|\d+)"])

        if pk_exact and sk_exact:
            return self._make_finding(
                rule_id="FIPS204-STATIC-017",
                title="Exact key lengths are checked",
                status="Passed",
                severity="Information",
                description="Public-key and private-key decode paths appear to enforce exact encoded lengths.",
                technical_explanation="Detected strict pk/sk length checks using expected constants.",
                impact="Exact key-length checks prevent malformed key acceptance.",
                mitigation="Retain strict checks before any unpack/decode operation.",
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-017",
            title="Exact key lengths are checked",
            status="Failed",
            severity="High",
            description="Public/private key decoding must require exact encoded lengths for selected parameter set.",
            technical_explanation=f"pk_exact={pk_exact}, sk_exact={sk_exact}",
            impact="Missing exact checks can allow malformed keys and undefined behavior.",
            mitigation="Add strict pk/sk length checks in public APIs and decode routines.",
        )

    def check_fips204_static_014(self) -> dict[str, Any]:
        """FIPS204-STATIC-018 — Required SHAKE functions are used."""
        all_code = "\n".join(code for _, code in self.all_files)
        has_shake128 = bool(re.search(r"shake128", all_code, re.IGNORECASE))
        has_shake256 = bool(re.search(r"shake256", all_code, re.IGNORECASE))
        unauthorized = []
        if re.search(r"\bsha256\b|SHA256", all_code):
            unauthorized.append("SHA-256")
        if re.search(r"\bsha512\b|SHA512", all_code):
            unauthorized.append("SHA-512")
        if re.search(r"blake2|blake3|\bblake\b", all_code, re.IGNORECASE):
            unauthorized.append("BLAKE")

        if has_shake128 and has_shake256 and not unauthorized:
            return self._make_finding(
                rule_id="FIPS204-STATIC-018",
                title="Required SHAKE functions are used",
                status="Passed",
                severity="Information",
                description="Detected SHAKE128 and SHAKE256 usage for ML-DSA processing with no obvious unauthorized hash substitution.",
                technical_explanation="Found call-site indicators for both SHAKE variants.",
                impact="Correct SHAKE usage is required by FIPS 204 internals.",
                mitigation="Keep SHAKE call sites aligned with standardized operations.",
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-018",
            title="Required SHAKE functions are used",
            status="Failed",
            severity="High",
            description="ML-DSA internal operations should use SHAKE128/SHAKE256 and avoid unauthorized substitutions.",
            technical_explanation=f"has_shake128={has_shake128}, has_shake256={has_shake256}, unauthorized={unauthorized}",
            impact="Incorrect hash/XOF selection can break conformance and interoperability.",
            mitigation="Use SHAKE128/SHAKE256 at required call sites and remove unauthorized substitutions.",
        )

    def check_fips204_static_015(self) -> dict[str, Any]:
        """FIPS204-STATIC-019 — SHAKE output lengths are explicit and correct."""
        explicit_calls = 0
        suspicious_calls = 0
        for _, code in self.all_files:
            for m in re.finditer(r"shake(?:128|256)\s*\([^\)]*\)", code, re.IGNORECASE):
                call = m.group(0)
                explicit_calls += 1
                if not re.search(r"\b(\d+|[A-Z_]*BYTES|outlen|len|mlen|n)\b", call):
                    suspicious_calls += 1

        if explicit_calls > 0 and suspicious_calls == 0:
            return self._make_finding(
                rule_id="FIPS204-STATIC-019",
                title="SHAKE output lengths are explicit and correct",
                status="Passed",
                severity="Information",
                description="SHAKE invocations appear to request explicit output lengths.",
                technical_explanation=f"explicit_calls={explicit_calls}, suspicious_calls={suspicious_calls}",
                impact="Explicit XOF output lengths reduce risk of digest-length assumptions.",
                mitigation="Continue using explicit, operation-specific output lengths.",
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-019",
            title="SHAKE output lengths are explicit and correct",
            status="Failed",
            severity="Medium",
            description="SHAKE invocations should use explicit, correct output lengths for each operation.",
            technical_explanation=f"explicit_calls={explicit_calls}, suspicious_calls={suspicious_calls}",
            impact="Ambiguous XOF output sizing can lead to non-conformant challenge/seed processing.",
            mitigation="Pass explicit length arguments/constants to each SHAKE output call.",
        )

    def check_fips204_static_016(self) -> dict[str, Any]:
        """FIPS204-STATIC-020 — Incremental SHAKE is finalized correctly."""
        all_code = "\n".join(code for _, code in self.all_files)
        has_init = bool(re.search(r"shake(?:128|256).*init|keccak.*init", all_code, re.IGNORECASE))
        has_absorb = bool(re.search(r"absorb", all_code, re.IGNORECASE))
        has_finalize = bool(re.search(r"final(?:ize)?", all_code, re.IGNORECASE))
        has_squeeze = bool(re.search(r"squeeze", all_code, re.IGNORECASE))

        if has_init and has_absorb and has_finalize and has_squeeze:
            return self._make_finding(
                rule_id="FIPS204-STATIC-020",
                title="Incremental SHAKE is finalized correctly",
                status="Passed",
                severity="Information",
                description="Incremental SHAKE/Keccak flow shows init, absorb, finalize, and squeeze stages.",
                technical_explanation="Detected all required phase indicators in codebase.",
                impact="Missing finalize/squeeze sequencing can produce incorrect outputs.",
                mitigation="Preserve required phase ordering in incremental APIs.",
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-020",
            title="Incremental SHAKE is finalized correctly",
            status="Failed",
            severity="Medium",
            description="Incremental SHAKE path should initialize, absorb, finalize, and then squeeze output.",
            technical_explanation=f"init={has_init}, absorb={has_absorb}, finalize={has_finalize}, squeeze={has_squeeze}",
            impact="Missing phases can break deterministic derivations and challenge generation.",
            mitigation="Ensure full incremental SHAKE lifecycle is implemented at each call site.",
        )

    def check_fips204_static_017(self) -> dict[str, Any]:
        """FIPS204-STATIC-021 — Hash input order follows the algorithm."""
        reordered = []
        for file_path, code in self.all_files:
            if re.search(r"absorb\s*\([^\)]*msg[^\)]*\)\s*;\s*[^\n]*absorb\s*\([^\)]*ctx", code, re.IGNORECASE | re.DOTALL):
                reordered.append(Path(file_path).name)

        if not reordered:
            return self._make_finding(
                rule_id="FIPS204-STATIC-021",
                title="Hash input order follows the algorithm",
                status="Passed",
                severity="Information",
                description="No obvious reordered absorb/concatenation patterns were detected.",
                technical_explanation="Heuristic scan found no strong msg-before-context ordering anomalies.",
                impact="Correct input order is required to recompute identical challenge values.",
                mitigation="Keep absorb/concatenation order aligned with the specification.",
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-021",
            title="Hash input order follows the algorithm",
            status="Failed",
            severity="High",
            description="Hash/XOF input concatenation order should follow FIPS 204 exactly.",
            technical_explanation="Potential reordered absorb pattern detected in: " + ", ".join(reordered[:5]),
            impact="Reordered inputs lead to non-interoperable signatures and verification failures.",
            mitigation="Review absorb sequence for seeds, identifiers, context, and message fields.",
        )

    def check_fips204_static_018(self) -> dict[str, Any]:
        """FIPS204-STATIC-022 — Domain separation is implemented."""
        all_code = "\n".join(code for _, code in self.all_files)
        has_domain_markers = bool(
            re.search(r"dom(?:ain)?[_-]?sep|prehash|hashml|ctxlen|context", all_code, re.IGNORECASE)
        )

        if has_domain_markers:
            return self._make_finding(
                rule_id="FIPS204-STATIC-022",
                title="Domain separation is implemented",
                status="Passed",
                severity="Information",
                description="Domain-separation/message-format indicators were detected for ML-DSA processing.",
                technical_explanation="Detected context/domain-separation related symbols or logic.",
                impact="Domain separation prevents mode confusion and cross-context misuse.",
                mitigation="Retain explicit domain separators for pure and prehash modes.",
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-022",
            title="Domain separation is implemented",
            status="Failed",
            severity="Medium",
            description="Pure ML-DSA and HashML-DSA should apply required domain-separation values and formatting.",
            technical_explanation="No strong domain-separation indicators were found.",
            impact="Missing separators can blur mode boundaries and break conformance.",
            mitigation="Implement explicit domain bytes and context formatting steps per mode.",
        )

    def check_fips204_static_019(self) -> dict[str, Any]:
        """FIPS204-STATIC-023 — Integer fields have fixed-width encoding."""
        all_code = "\n".join(code for _, code in self.all_files)
        fixed_width = bool(re.search(r"uint8_t|uint16_t|store16|store32|to_bytes|little[_-]?endian", all_code, re.IGNORECASE))
        risky_direct = bool(re.search(r"absorb\s*\([^\)]*(?:int|size_t|unsigned)\s*\*", all_code, re.IGNORECASE))

        if fixed_width and not risky_direct:
            return self._make_finding(
                rule_id="FIPS204-STATIC-023",
                title="Integer fields have fixed-width encoding",
                status="Passed",
                severity="Information",
                description="Fixed-width integer encoding helpers/types were detected before hash absorption.",
                technical_explanation="Detected uint8_t/uint16_t or explicit byte-store helpers without obvious direct native-int hashing.",
                impact="Fixed-width encoding avoids platform-dependent hash input representation.",
                mitigation="Continue encoding indices/nonces/counters as explicit byte sequences.",
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-023",
            title="Integer fields have fixed-width encoding",
            status="Failed",
            severity="Medium",
            description="Matrix indices, nonces, counters, and lengths should be encoded with fixed width and byte order.",
            technical_explanation=f"fixed_width_indicators={fixed_width}, risky_native_int_absorb={risky_direct}",
            impact="Platform-dependent integer hashing can break deterministic behavior across targets.",
            mitigation="Serialize integer fields into defined byte arrays before SHAKE absorption.",
        )

    def check_fips204_static_020(self) -> dict[str, Any]:
        """FIPS204-STATIC-024 — Key-generation seed length is correct."""
        seed_candidates = self._extract_symbol_candidates(self.PARAM_SYMBOLS["seed_bytes"])
        has_seed32_const = any(v == 32 for _, _, _, v in seed_candidates)

        all_code = self._all_code()
        has_seed32_call = bool(
            re.search(r"randombytes\s*\([^\)]*,\s*32\s*\)|keypair\s*\([^\)]*32", all_code, re.IGNORECASE)
        )

        if has_seed32_const or has_seed32_call:
            file_name, line = (Path(seed_candidates[0][0]).name, seed_candidates[0][1]) if seed_candidates else ("-", "-")
            return self._make_finding(
                rule_id="FIPS204-STATIC-024",
                title="Key-generation seed length is correct",
                status="Passed",
                severity="Information",
                description="Key-generation path includes evidence of 32-byte seed handling.",
                technical_explanation=f"has_seed32_const={has_seed32_const}, has_seed32_call={has_seed32_call}",
                impact="Correct seed length is required for standardized key generation.",
                mitigation="Keep internal keygen seed input fixed at 32 bytes.",
                file=file_name,
                line=line,
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-024",
            title="Key-generation seed length is correct",
            status="Failed",
            severity="High",
            description="Internal key generation should accept/derive a 32-byte seed.",
            technical_explanation="No strong 32-byte seed constant/call-site indicator was found.",
            impact="Wrong seed length breaks key derivation compatibility and conformance.",
            mitigation="Define SEEDBYTES=32 and enforce 32-byte seed flow in key generation.",
        )

    def check_fips204_static_021(self) -> dict[str, Any]:
        """FIPS204-STATIC-025 — Key-generation seed expansion is correct."""
        all_code = self._all_code()
        has_keygen_path = self._contains_any(all_code, [r"crypto_sign_keypair", r"ml_dsa.*keypair", r"keypair"]) 
        has_shake_expansion = self._contains_any(
            all_code,
            [r"shake256", r"shake128", r"expand.*seed", r"rho|rhoprime|key|tr"],
        )

        if has_keygen_path and has_shake_expansion:
            return self._make_finding(
                rule_id="FIPS204-STATIC-025",
                title="Key-generation seed expansion is correct",
                status="Passed",
                severity="Information",
                description="Key-generation flow contains indicators that seed expansion is performed via SHAKE-based processing.",
                technical_explanation="Detected keypair path together with SHAKE/seed-expansion indicators.",
                impact="Correct seed expansion is required to derive standardized internal key material.",
                mitigation="Preserve SHAKE-based keygen expansion sequence defined by FIPS 204.",
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-025",
            title="Key-generation seed expansion is correct",
            status="Failed",
            severity="High",
            description="Key-generation seed should be expanded through prescribed SHAKE processing into required internal values.",
            technical_explanation=f"has_keygen_path={has_keygen_path}, has_shake_expansion={has_shake_expansion}",
            impact="Incorrect expansion may produce non-conformant keys and break interoperability.",
            mitigation="Use SHAKE-based expansion directly in key generation as required by ML-DSA.",
        )

    def check_fips204_static_022(self) -> dict[str, Any]:
        """FIPS204-STATIC-026 — Parameter set is bound to seed expansion."""
        all_code = self._all_code()
        has_k_l_constants = self._contains_any(all_code, [r"\bK\b", r"\bL\b", r"DILITHIUM_K", r"DILITHIUM_L", r"ML_DSA_K", r"ML_DSA_L"])
        has_seed_absorb_with_params = self._contains_any(
            all_code,
            [
                r"absorb[^\n]*\bK\b",
                r"absorb[^\n]*\bL\b",
                r"seed[^\n]*K[^\n]*L",
                r"k\s*<<|l\s*<<",
            ],
        )

        if has_k_l_constants and has_seed_absorb_with_params:
            return self._make_finding(
                rule_id="FIPS204-STATIC-026",
                title="Parameter set is bound to seed expansion",
                status="Passed",
                severity="Information",
                description="Seed-expansion path includes parameter-set binding indicators for k and l.",
                technical_explanation="Detected K/L constants and absorb/seed usage patterns involving those parameters.",
                impact="Binding seed expansion to k/l prevents cross-parameter ambiguity.",
                mitigation="Keep k and l explicitly included in seed expansion inputs.",
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-026",
            title="Parameter set is bound to seed expansion",
            status="Failed",
            severity="High",
            description="Seed expansion should bind generated material to selected k and l values.",
            technical_explanation=f"has_k_l_constants={has_k_l_constants}, has_seed_absorb_with_params={has_seed_absorb_with_params}",
            impact="Missing k/l binding can produce parameter-set ambiguity and non-conformant derivations.",
            mitigation="Include k and l in standardized seed-expansion input fields.",
        )

    def check_fips204_static_023(self) -> dict[str, Any]:
        """FIPS204-STATIC-027 — Public matrix uses the correct seed."""
        all_code = self._all_code()
        has_matrix_expand = self._contains_any(all_code, [r"expand.*matrix", r"gen_matrix", r"polyvec_matrix", r"mat.*expand"])
        uses_public_seed = self._contains_any(all_code, [r"rho", r"publicseed", r"seed_a", r"seedpub"])
        uses_secret_seed_for_matrix = self._contains_any(all_code, [r"expand.*matrix[^\n]*rhoprime", r"gen_matrix[^\n]*secret", r"matrix[^\n]*key[^\n]*secret"])

        if has_matrix_expand and uses_public_seed and not uses_secret_seed_for_matrix:
            return self._make_finding(
                rule_id="FIPS204-STATIC-027",
                title="Public matrix uses the correct seed",
                status="Passed",
                severity="Information",
                description="Matrix expansion appears bound to public-seed material (e.g., rho/publicseed).",
                technical_explanation="Detected matrix-expansion indicators using public-seed symbols without clear secret-seed substitution.",
                impact="Using the public seed is required for deterministic standardized matrix generation.",
                mitigation="Keep matrix expansion input tied to the public seed only.",
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-027",
            title="Public matrix uses the correct seed",
            status="Failed",
            severity="High",
            description="Matrix expansion should derive coefficients from the public seed, not private/unrelated material.",
            technical_explanation=(
                f"has_matrix_expand={has_matrix_expand}, uses_public_seed={uses_public_seed}, "
                f"uses_secret_seed_for_matrix={uses_secret_seed_for_matrix}"
            ),
            impact="Wrong seed source changes matrix generation and breaks conformance.",
            mitigation="Route matrix expansion through the standardized public-seed path.",
        )

    def check_fips204_static_024(self) -> dict[str, Any]:
        """FIPS204-STATIC-028 — Matrix indices are not reversed."""
        all_code = self._all_code()
        has_index_use = self._contains_any(all_code, [r"for\s*\([^\)]*i", r"for\s*\([^\)]*j", r"xof_absorb", r"shake.*absorb"])
        reversed_pattern = self._contains_any(
            all_code,
            [
                r"xof_absorb[^\n]*j[^\n]*i",
                r"absorb[^\n]*col[^\n]*row",
            ],
        )
        correct_pattern = self._contains_any(
            all_code,
            [
                r"xof_absorb[^\n]*i[^\n]*j",
                r"absorb[^\n]*row[^\n]*col",
            ],
        )

        if has_index_use and correct_pattern and not reversed_pattern:
            return self._make_finding(
                rule_id="FIPS204-STATIC-028",
                title="Matrix indices are not reversed",
                status="Passed",
                severity="Information",
                description="Matrix expansion index-order indicators appear consistent with row-then-column absorption.",
                technical_explanation="Found i/j (row/col) absorb ordering without strong reversed-order patterns.",
                impact="Index order controls deterministic matrix generation.",
                mitigation="Preserve standardized row/column absorb order.",
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-028",
            title="Matrix indices are not reversed",
            status="Failed",
            severity="High",
            description="Matrix row/column indices should be absorbed in the required order during expansion.",
            technical_explanation=f"has_index_use={has_index_use}, correct_pattern={correct_pattern}, reversed_pattern={reversed_pattern}",
            impact="Reversed indices generate a different matrix and break interoperability.",
            mitigation="Ensure absorb order follows standardized row/column sequence.",
        )

    def check_fips204_static_025(self) -> dict[str, Any]:
        """FIPS204-STATIC-029 — Secret vectors use the correct sampler."""
        all_code = self._all_code()
        has_eta_sampler = self._contains_any(
            all_code,
            [r"poly_uniform_eta", r"sample.*eta", r"rej_eta", r"cbd", r"uniform_eta"],
        )
        has_eta_param = bool(self._extract_symbol_candidates(self.PARAM_SYMBOLS["eta"]))

        if has_eta_sampler and has_eta_param:
            return self._make_finding(
                rule_id="FIPS204-STATIC-029",
                title="Secret vectors use the correct sampler",
                status="Passed",
                severity="Information",
                description="Secret-vector sampling appears to use eta-bounded sampler indicators.",
                technical_explanation="Detected eta constants together with eta/CBD sampling routines.",
                impact="Correct secret sampler is required for standardized key distribution.",
                mitigation="Use eta-bound sampler matching selected parameter set.",
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-029",
            title="Secret vectors use the correct sampler",
            status="Failed",
            severity="High",
            description="Secret vectors should be sampled with the required bounded sampler for selected eta.",
            technical_explanation=f"has_eta_sampler={has_eta_sampler}, has_eta_param={has_eta_param}",
            impact="Wrong sampler alters secret distribution and breaks conformance.",
            mitigation="Implement/route secret sampling through the eta-specific standardized sampler.",
        )

    def check_fips204_static_026(self) -> dict[str, Any]:
        """FIPS204-STATIC-030 — Secret-sampling nonces are unique."""
        all_code = self._all_code()
        has_nonce = self._contains_any(all_code, [r"nonce", r"counter"])
        has_nonce_increment = self._contains_any(all_code, [r"nonce\s*\+\+", r"nonce\s*\+=\s*1", r"nonce\s*=\s*nonce\s*\+\s*1", r"counter\s*\+\+"])
        has_reset_pattern = self._contains_any(all_code, [r"nonce\s*=\s*0\s*;[^\n]*nonce\s*=\s*0", r"counter\s*=\s*0\s*;[^\n]*counter\s*=\s*0"])

        if has_nonce and has_nonce_increment and not has_reset_pattern:
            return self._make_finding(
                rule_id="FIPS204-STATIC-030",
                title="Secret-sampling nonces are unique",
                status="Passed",
                severity="Information",
                description="Secret-sampling nonce/counter appears incremented without obvious reset/reuse pattern.",
                technical_explanation="Detected nonce/counter symbols with increment progression patterns.",
                impact="Unique nonces are required to prevent repeated secret-sampling streams.",
                mitigation="Keep nonce/counter monotonic and unique per sampled secret polynomial.",
            )

        return self._make_finding(
            rule_id="FIPS204-STATIC-030",
            title="Secret-sampling nonces are unique",
            status="Failed",
            severity="High",
            description="Each secret polynomial should receive a unique nonce/counter during key generation.",
            technical_explanation=f"has_nonce={has_nonce}, has_nonce_increment={has_nonce_increment}, has_reset_pattern={has_reset_pattern}",
            impact="Duplicated/reset nonces can repeat sampling streams and violate conformance assumptions.",
            mitigation="Advance nonce/counter per polynomial and avoid resets within one keygen flow.",
        )

    def check_fips204_static_031(self) -> dict[str, Any]:
        """FIPS204-STATIC-031 — Matrix-vector multiplication dimensions are correct."""
        all_code = self._all_code()
        values = self._collect_param_values()
        selected = self._selected_param_set(values)
        k = self.PARAM_SET_CONSTANTS[selected]["k"] if selected else None
        l = self.PARAM_SET_CONSTANTS[selected]["l"] if selected else None
        has_matmul = self._contains_any(all_code, [r"mat.*vec", r"matrix.*vector", r"polyvec_matrix", r"pointwise_montgomery"])
        has_k_loop = bool(k and re.search(rf"for\s*\([^;]*;\s*[^;]*<\s*(?:K|{k})\s*;", all_code))
        has_l_loop = bool(l and re.search(rf"for\s*\([^;]*;\s*[^;]*<\s*(?:L|{l})\s*;", all_code))

        if has_matmul and has_k_loop and has_l_loop:
            return self._make_finding(
                rule_id="FIPS204-STATIC-031",
                title="Matrix-vector multiplication dimensions are correct",
                status="Passed",
                severity="Information",
                description="Detected k×l by l-dimension multiplication indicators producing k outputs.",
                technical_explanation=f"selected={selected}, has_matmul={has_matmul}, k_loop={has_k_loop}, l_loop={has_l_loop}",
                impact="Dimension consistency is required for correct key-generation arithmetic.",
                mitigation="Keep matrix/vector loops and allocations tied to k and l.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-031",
            title="Matrix-vector multiplication dimensions are correct",
            status="Failed",
            severity="High",
            description="Key generation should multiply k×l matrix by l-vector to produce k-vector.",
            technical_explanation=f"selected={selected}, has_matmul={has_matmul}, k_loop={has_k_loop}, l_loop={has_l_loop}",
            impact="Wrong dimensions break key generation correctness.",
            mitigation="Align matrix/vector dimensions and loops with selected k/l.",
        )

    def check_fips204_static_032(self) -> dict[str, Any]:
        """FIPS204-STATIC-032 — Power2Round is used during key generation."""
        all_code = self._all_code()
        has_power2round = self._contains_any(all_code, [r"power2round", r"poly_power2round", r"round2", r"decompose"])
        has_keygen = self._contains_any(all_code, [r"keypair", r"crypto_sign_keypair", r"ml_dsa.*keygen"])
        if has_power2round and has_keygen:
            return self._make_finding(
                rule_id="FIPS204-STATIC-032",
                title="Power2Round is used during key generation",
                status="Passed",
                severity="Information",
                description="Key-generation path includes Power2Round/decomposition indicators for public vector derivation.",
                technical_explanation=f"has_power2round={has_power2round}, has_keygen={has_keygen}",
                impact="Power2Round usage is required for standardized key output decomposition.",
                mitigation="Retain Power2Round in key-generation public-vector construction.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-032",
            title="Power2Round is used during key generation",
            status="Failed",
            severity="High",
            description="Key generation should apply required Power2Round decomposition.",
            technical_explanation=f"has_power2round={has_power2round}, has_keygen={has_keygen}",
            impact="Missing decomposition can produce non-conformant public key components.",
            mitigation="Apply Power2Round in key-generation flow before encoding public vector fields.",
        )

    def check_fips204_static_033(self) -> dict[str, Any]:
        """FIPS204-STATIC-033 — Public-key field order is correct."""
        all_code = self._all_code()
        has_pack_pk = self._contains_any(all_code, [r"pack_pk", r"pack_public", r"encode.*public"])
        rho_then_t1 = bool(re.search(r"rho[\s\S]{0,220}t1", all_code, re.IGNORECASE))
        t1_then_rho = bool(re.search(r"t1[\s\S]{0,220}rho", all_code, re.IGNORECASE))
        if has_pack_pk and rho_then_t1 and not t1_then_rho:
            return self._make_finding(
                rule_id="FIPS204-STATIC-033",
                title="Public-key field order is correct",
                status="Passed",
                severity="Information",
                description="Public-key encoding indicators suggest required field ordering is respected.",
                technical_explanation="Detected pack/encode path with rho before t1 and no strong reverse-order pattern.",
                impact="Field order affects interoperability of encoded keys.",
                mitigation="Maintain standardized public-key field order during encoding.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-033",
            title="Public-key field order is correct",
            status="Failed",
            severity="High",
            description="Public-key encoding must place required fields in standardized order.",
            technical_explanation=f"has_pack_pk={has_pack_pk}, rho_then_t1={rho_then_t1}, t1_then_rho={t1_then_rho}",
            impact="Wrong order can make keys incompatible with conforming implementations.",
            mitigation="Encode public key fields in required sequence.",
        )

    def check_fips204_static_034(self) -> dict[str, Any]:
        """FIPS204-STATIC-034 — Private-key field order is correct."""
        all_code = self._all_code()
        has_pack_sk = self._contains_any(all_code, [r"pack_sk", r"pack_secret", r"encode.*secret"])
        order_hint = bool(re.search(r"rho[\s\S]{0,300}k|rho[\s\S]{0,300}tr|tr[\s\S]{0,300}s1", all_code, re.IGNORECASE))
        if has_pack_sk and order_hint:
            return self._make_finding(
                rule_id="FIPS204-STATIC-034",
                title="Private-key field order is correct",
                status="Passed",
                severity="Information",
                description="Private-key packing path contains indicators of standardized field sequencing.",
                technical_explanation=f"has_pack_sk={has_pack_sk}, order_hint={order_hint}",
                impact="Private-key field order is required for decoding/interoperability.",
                mitigation="Keep private-key encoding fields in required order and format.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-034",
            title="Private-key field order is correct",
            status="Failed",
            severity="High",
            description="Private-key encoding should include all required fields in standardized order.",
            technical_explanation=f"has_pack_sk={has_pack_sk}, order_hint={order_hint}",
            impact="Incorrect field order can break decode/signing behavior.",
            mitigation="Review private-key pack/unpack routines for required field sequence.",
        )

    def check_fips204_static_035(self) -> dict[str, Any]:
        """FIPS204-STATIC-035 — Public-key hash is computed from the encoded key."""
        all_code = self._all_code()
        has_hash_pk = self._contains_any(all_code, [r"shake256", r"hash", r"tr", r"publickey", r"pk"]) and self._contains_any(all_code, [r"CRYPTO_PUBLICKEYBYTES", r"PUBLICKEYBYTES", r"pklen"])
        if has_hash_pk:
            return self._make_finding(
                rule_id="FIPS204-STATIC-035",
                title="Public-key hash is computed from the encoded key",
                status="Passed",
                severity="Information",
                description="Detected indicators that the encoded public key is hashed with SHAKE-based processing.",
                technical_explanation="Found SHAKE/hash references together with public-key length/material symbols.",
                impact="Hashing encoded public key is required for standardized binding.",
                mitigation="Ensure full encoded public key bytes are hashed with required SHAKE variant/length.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-035",
            title="Public-key hash is computed from the encoded key",
            status="Failed",
            severity="High",
            description="Implementation should hash full encoded public key with required SHAKE operation and output length.",
            technical_explanation="No strong public-key hash path indicators were found.",
            impact="Missing/incorrect public-key hash can break signing/verification binding.",
            mitigation="Compute hash over complete encoded public key in key-generation flow.",
        )

    def check_fips204_static_036(self) -> dict[str, Any]:
        """FIPS204-STATIC-036 — Randomness failure is propagated."""
        all_code = self._all_code()
        has_rng = self._contains_any(all_code, [r"randombytes", r"getrandom", r"rng", r"entropy"])
        has_failure_check = self._contains_any(all_code, [r"randombytes[^\n]*!=\s*0", r"if\s*\([^\)]*rng[^\)]*fail", r"return\s*-1", r"goto\s+fail"])
        bad_fallback = self._contains_any(all_code, [r"memset\s*\([^\)]*0", r"fixed_seed", r"seed\s*=\s*0", r"uninitialized"])
        if has_rng and has_failure_check and not bad_fallback:
            return self._make_finding(
                rule_id="FIPS204-STATIC-036",
                title="Randomness failure is propagated",
                status="Passed",
                severity="Information",
                description="Randomness source usage includes failure-path indicators and no obvious unsafe seed fallback.",
                technical_explanation=f"has_rng={has_rng}, has_failure_check={has_failure_check}, bad_fallback={bad_fallback}",
                impact="Proper failure propagation avoids unsafe key-generation seeds.",
                mitigation="Keep RNG failures visible to caller and avoid fallback seeds.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-036",
            title="Randomness failure is propagated",
            status="Failed",
            severity="High",
            description="Key-generation API should propagate randomness failure and avoid zero/fixed/partial seed fallbacks.",
            technical_explanation=f"has_rng={has_rng}, has_failure_check={has_failure_check}, bad_fallback={bad_fallback}",
            impact="Unsafe fallback seeds can produce predictable/non-conformant keys.",
            mitigation="Fail fast on RNG errors and never substitute weak fallback seed material.",
        )

    def check_fips204_static_037(self) -> dict[str, Any]:
        """FIPS204-STATIC-037 — Context length is limited to 255 bytes."""
        all_code = self._all_code()
        has_ctx_limit = self._contains_any(all_code, [r"ctxlen\s*>\s*255", r"context_len\s*>\s*255", r"if\s*\([^\)]*255[^\)]*\)\s*return"])
        if has_ctx_limit:
            return self._make_finding(
                rule_id="FIPS204-STATIC-037",
                title="Context length is limited to 255 bytes",
                status="Passed",
                severity="Information",
                description="Detected explicit context-length upper bound checks at 255 bytes.",
                technical_explanation="Found context-length check patterns enforcing >255 rejection.",
                impact="Length bound is required for standardized context representation.",
                mitigation="Retain explicit reject-on-overflow checks for context length.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-037",
            title="Context length is limited to 255 bytes",
            status="Failed",
            severity="Medium",
            description="Signing/verification should reject contexts longer than 255 bytes.",
            technical_explanation="No strong >255 context-length rejection indicator found.",
            impact="Missing bound checks can lead to non-conformant formatting.",
            mitigation="Add explicit context length validation before message formatting.",
        )

    def check_fips204_static_038(self) -> dict[str, Any]:
        """FIPS204-STATIC-038 — Context length is encoded in one byte."""
        all_code = self._all_code()
        has_one_byte_len = self._contains_any(all_code, [r"uint8_t\s+ctxlen", r"buf\[0\]\s*=\s*ctxlen", r"\(uint8_t\)\s*ctxlen"])
        has_ctx_copy = self._contains_any(all_code, [r"memcpy\s*\([^\)]*ctx", r"absorb\s*\([^\)]*ctx[^\)]*ctxlen"])
        if has_one_byte_len and has_ctx_copy:
            return self._make_finding(
                rule_id="FIPS204-STATIC-038",
                title="Context length is encoded in one byte",
                status="Passed",
                severity="Information",
                description="Detected one-byte context-length encoding and context-byte inclusion patterns.",
                technical_explanation=f"has_one_byte_len={has_one_byte_len}, has_ctx_copy={has_ctx_copy}",
                impact="Correct one-byte length framing is required by standardized context formatting.",
                mitigation="Preserve [len-byte || context-bytes] representation in both sign and verify paths.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-038",
            title="Context length is encoded in one byte",
            status="Failed",
            severity="Medium",
            description="Context representation should include exactly one-byte context length followed by context bytes.",
            technical_explanation=f"has_one_byte_len={has_one_byte_len}, has_ctx_copy={has_ctx_copy}",
            impact="Incorrect framing breaks message representative reconstruction.",
            mitigation="Encode context length in one byte and append exact context bytes.",
        )

    def check_fips204_static_039(self) -> dict[str, Any]:
        """FIPS204-STATIC-039 — Empty contexts are handled consistently."""
        all_code = self._all_code()
        has_empty_ctx_logic = self._contains_any(all_code, [r"ctxlen\s*==\s*0", r"context_len\s*==\s*0", r"if\s*\([^\)]*ctx[^\)]*NULL[^\)]*\)"])
        sign_path = self._contains_any(all_code, [r"sign", r"signature"])
        verify_path = self._contains_any(all_code, [r"verify", r"verification"])
        if has_empty_ctx_logic and sign_path and verify_path:
            return self._make_finding(
                rule_id="FIPS204-STATIC-039",
                title="Empty contexts are handled consistently",
                status="Passed",
                severity="Information",
                description="Found empty-context handling indicators in codebase with both signing and verification paths present.",
                technical_explanation=f"has_empty_ctx_logic={has_empty_ctx_logic}, sign_path={sign_path}, verify_path={verify_path}",
                impact="Consistent empty-context handling is required for interoperability.",
                mitigation="Use identical empty-context representation across sign/verify.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-039",
            title="Empty contexts are handled consistently",
            status="Failed",
            severity="Medium",
            description="Signing and verification should treat empty context with the same standardized representation.",
            technical_explanation=f"has_empty_ctx_logic={has_empty_ctx_logic}, sign_path={sign_path}, verify_path={verify_path}",
            impact="Inconsistent empty-context formatting can cause valid signatures to fail.",
            mitigation="Align empty-context handling logic in both paths.",
        )

    def check_fips204_static_040(self) -> dict[str, Any]:
        """FIPS204-STATIC-040 — Signing and verification use identical formatting."""
        all_code = self._all_code()
        has_shared_formatter = self._contains_any(all_code, [r"format.*message", r"msg_repr", r"build.*context", r"compute_mu"]) 
        has_sign = self._contains_any(all_code, [r"sign"]) 
        has_verify = self._contains_any(all_code, [r"verify"]) 
        if has_shared_formatter and has_sign and has_verify:
            return self._make_finding(
                rule_id="FIPS204-STATIC-040",
                title="Signing and verification use identical formatting",
                status="Passed",
                severity="Information",
                description="Detected shared/parallel message-formatting indicators used by signing and verification paths.",
                technical_explanation=f"has_shared_formatter={has_shared_formatter}, has_sign={has_sign}, has_verify={has_verify}",
                impact="Consistent formatting is required to recompute matching challenge input.",
                mitigation="Keep shared standardized message-representation construction.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-040",
            title="Signing and verification use identical formatting",
            status="Failed",
            severity="High",
            description="Signing and verification should construct identical message representation fields and order.",
            technical_explanation=f"has_shared_formatter={has_shared_formatter}, has_sign={has_sign}, has_verify={has_verify}",
            impact="Formatting divergence causes verification failures/interoperability issues.",
            mitigation="Use the same formatting routine or strictly mirrored logic for both paths.",
        )

    def check_fips204_static_041(self) -> dict[str, Any]:
        """FIPS204-STATIC-041 — Pure ML-DSA and HashML-DSA are separated."""
        all_code = self._all_code()
        has_pure = self._contains_any(all_code, [r"pure", r"ml_dsa_sign", r"ml_dsa_verify"]) 
        has_prehash = self._contains_any(all_code, [r"prehash", r"hashml", r"hash_mldsa", r"ph"])
        has_mode_branch = self._contains_any(all_code, [r"if\s*\([^\)]*prehash", r"switch\s*\([^\)]*mode"])
        if has_pure and has_prehash and has_mode_branch:
            return self._make_finding(
                rule_id="FIPS204-STATIC-041",
                title="Pure ML-DSA and HashML-DSA are separated",
                status="Passed",
                severity="Information",
                description="Detected separate pure/prehash path indicators with explicit mode branching.",
                technical_explanation=f"has_pure={has_pure}, has_prehash={has_prehash}, has_mode_branch={has_mode_branch}",
                impact="Mode separation prevents accidental interchange of pure and prehash formats.",
                mitigation="Retain explicit mode split for pure ML-DSA and HashML-DSA.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-041",
            title="Pure ML-DSA and HashML-DSA are separated",
            status="Failed",
            severity="High",
            description="Pure and prehash interfaces should use distinct standardized message processing.",
            technical_explanation=f"has_pure={has_pure}, has_prehash={has_prehash}, has_mode_branch={has_mode_branch}",
            impact="Interchangeable handling can break conformance and signature interpretation.",
            mitigation="Add explicit interface/mode separation and per-mode formatting paths.",
        )

    def check_fips204_static_042(self) -> dict[str, Any]:
        """FIPS204-STATIC-042 — Prehash identifiers are validated."""
        all_code = self._all_code()
        has_id_check = self._contains_any(all_code, [r"prehash_id", r"phid", r"oid", r"if\s*\([^\)]*id[^\)]*==", r"switch\s*\([^\)]*id"])
        has_allowlist = self._contains_any(all_code, [r"SHA256|SHA512|SHAKE128|SHAKE256|case\s+", r"unsupported", r"return\s*-1"])
        if has_id_check and has_allowlist:
            return self._make_finding(
                rule_id="FIPS204-STATIC-042",
                title="Prehash identifiers are validated",
                status="Passed",
                severity="Information",
                description="Prehash-identifier validation patterns were detected.",
                technical_explanation=f"has_id_check={has_id_check}, has_allowlist={has_allowlist}",
                impact="Identifier validation prevents unsupported/incorrect prehash usage.",
                mitigation="Keep allowlist validation and reject unknown identifiers.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-042",
            title="Prehash identifiers are validated",
            status="Failed",
            severity="Medium",
            description="HashML-DSA prehash identifiers should be validated against supported set.",
            technical_explanation=f"has_id_check={has_id_check}, has_allowlist={has_allowlist}",
            impact="Unchecked IDs can cause mismatched prehash processing.",
            mitigation="Add strict identifier validation and explicit reject behavior.",
        )

    def check_fips204_static_043(self) -> dict[str, Any]:
        """FIPS204-STATIC-043 — Private-key decoding is validated before signing."""
        all_code = self._all_code()
        has_unpack_sk = self._contains_any(all_code, [r"unpack_sk", r"decode.*secret", r"parse.*sk"])
        has_len_check = self._contains_any(all_code, [r"sk(?:len|_len)?\s*!=\s*(?:CRYPTO_SECRETKEYBYTES|SECRETKEYBYTES|ML_DSA_SECRETKEYBYTES|\d+)"])
        has_error_path = self._contains_any(all_code, [r"if\s*\([^\)]*unpack[^\)]*\)\s*return", r"if\s*\([^\)]*decode[^\)]*\)\s*return", r"return\s*-1"])
        if has_unpack_sk and has_len_check and has_error_path:
            return self._make_finding(
                rule_id="FIPS204-STATIC-043",
                title="Private-key decoding is validated before signing",
                status="Passed",
                severity="Information",
                description="Signing path includes private-key length/decode checks with explicit failure handling.",
                technical_explanation=f"has_unpack_sk={has_unpack_sk}, has_len_check={has_len_check}, has_error_path={has_error_path}",
                impact="Early decode validation prevents signing with malformed secret keys.",
                mitigation="Keep strict private-key validation before using decoded fields.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-043",
            title="Private-key decoding is validated before signing",
            status="Failed",
            severity="High",
            description="Signing should validate private-key length and decode status before using key material.",
            technical_explanation=f"has_unpack_sk={has_unpack_sk}, has_len_check={has_len_check}, has_error_path={has_error_path}",
            impact="Missing checks can accept malformed keys and produce undefined behavior.",
            mitigation="Add strict decode+length checks and fail-fast before signing logic.",
        )

    def check_fips204_static_044(self) -> dict[str, Any]:
        """FIPS204-STATIC-044 — Signing randomness length is correct."""
        all_code = self._all_code()
        has_sign_rng_32 = self._contains_any(
            all_code,
            [
                r"sign[^\n]*random[^\n]*32",
                r"randombytes\s*\([^\)]*,\s*32\s*\)",
                r"rnd(?:len|_len)?\s*==\s*32",
            ],
        )
        if has_sign_rng_32:
            return self._make_finding(
                rule_id="FIPS204-STATIC-044",
                title="Signing randomness length is correct",
                status="Passed",
                severity="Information",
                description="Detected 32-byte signing-randomness indicators in signing path.",
                technical_explanation="Found 32-byte random input checks/calls associated with signing.",
                impact="Correct randomness length is required for standardized signing behavior.",
                mitigation="Keep internal signing randomness input fixed at 32 bytes.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-044",
            title="Signing randomness length is correct",
            status="Failed",
            severity="High",
            description="Internal signing operation should receive a 32-byte randomness value.",
            technical_explanation="No strong 32-byte signing-randomness indicator found.",
            impact="Wrong randomness length can break conformance and deterministic/hedged behavior.",
            mitigation="Validate/derive signing randomness with exact 32-byte length.",
        )

    def check_fips204_static_045(self) -> dict[str, Any]:
        """FIPS204-STATIC-045 — Deterministic signing uses the standardized input."""
        all_code = self._all_code()
        has_det_mode = self._contains_any(all_code, [r"deterministic", r"det_sign", r"mode.*det"])
        has_std_inputs = self._contains_any(all_code, [r"tr", r"mu", r"rhoprime", r"shake256", r"sign_randomness"])
        custom_derivation = self._contains_any(all_code, [r"custom", r"ad[_-]?hoc", r"debug_seed"])

        if has_det_mode and has_std_inputs and not custom_derivation:
            return self._make_finding(
                rule_id="FIPS204-STATIC-045",
                title="Deterministic signing uses the standardized input",
                status="Passed",
                severity="Information",
                description="Deterministic signing path shows standardized input-derivation indicators.",
                technical_explanation=f"has_det_mode={has_det_mode}, has_std_inputs={has_std_inputs}, custom_derivation={custom_derivation}",
                impact="Standardized deterministic derivation is required for conformant reproducibility.",
                mitigation="Keep deterministic randomness initialization aligned with FIPS 204 inputs.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-045",
            title="Deterministic signing uses the standardized input",
            status="Failed",
            severity="High",
            description="Deterministic signing should initialize internal randomness with the standardized FIPS 204 derivation.",
            technical_explanation=f"has_det_mode={has_det_mode}, has_std_inputs={has_std_inputs}, custom_derivation={custom_derivation}",
            impact="Custom derivations can break interoperability and expected deterministic behavior.",
            mitigation="Use only standardized deterministic input derivation.",
        )

    def check_fips204_static_046(self) -> dict[str, Any]:
        """FIPS204-STATIC-046 — Randomized signing requests fresh randomness."""
        all_code = self._all_code()
        has_random_sign = self._contains_any(all_code, [r"randomized", r"hedged", r"randombytes", r"sign_random"])
        per_call_rng = self._contains_any(all_code, [r"randombytes\s*\([^\)]*\)", r"getrandom\s*\("])
        reused_buffer = self._contains_any(all_code, [r"static\s+.*rand", r"global.*rand", r"reuse.*random"])
        if has_random_sign and per_call_rng and not reused_buffer:
            return self._make_finding(
                rule_id="FIPS204-STATIC-046",
                title="Randomized signing requests fresh randomness",
                status="Passed",
                severity="Information",
                description="Randomized/hedged signing path appears to request fresh randomness per signature.",
                technical_explanation=f"has_random_sign={has_random_sign}, per_call_rng={per_call_rng}, reused_buffer={reused_buffer}",
                impact="Fresh randomness is required for secure randomized signing behavior.",
                mitigation="Request new randomness for every signing operation.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-046",
            title="Randomized signing requests fresh randomness",
            status="Failed",
            severity="High",
            description="Randomized/hedged signing should obtain fresh randomness for each signature.",
            technical_explanation=f"has_random_sign={has_random_sign}, per_call_rng={per_call_rng}, reused_buffer={reused_buffer}",
            impact="Reused randomness can weaken signatures and violate standardized behavior.",
            mitigation="Ensure randomness is newly requested each signing call.",
        )

    def check_fips204_static_047(self) -> dict[str, Any]:
        """FIPS204-STATIC-047 — Signing randomness failure causes failure."""
        all_code = self._all_code()
        rng_fail_check = self._contains_any(all_code, [r"randombytes[^\n]*!=\s*0", r"if\s*\([^\)]*rng[^\)]*fail", r"return\s*-1"])
        unsafe_fallback = self._contains_any(all_code, [r"memset\s*\([^\)]*0", r"fixed_seed", r"uninitialized", r"continue\s*;\s*//.*rng"])
        if rng_fail_check and not unsafe_fallback:
            return self._make_finding(
                rule_id="FIPS204-STATIC-047",
                title="Signing randomness failure causes failure",
                status="Passed",
                severity="Information",
                description="Randomness failure checks are present with no obvious unsafe fallback path.",
                technical_explanation=f"rng_fail_check={rng_fail_check}, unsafe_fallback={unsafe_fallback}",
                impact="Failing on randomness errors prevents unsafe signature generation.",
                mitigation="Propagate RNG errors and abort signing on failure.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-047",
            title="Signing randomness failure causes failure",
            status="Failed",
            severity="High",
            description="Signing should fail when randomness provider fails; no zero/repeated/uninitialized fallback should be used.",
            technical_explanation=f"rng_fail_check={rng_fail_check}, unsafe_fallback={unsafe_fallback}",
            impact="Unsafe fallback randomness can cause predictable or invalid signatures.",
            mitigation="Abort signing immediately on RNG failure and return error.",
        )

    def check_fips204_static_048(self) -> dict[str, Any]:
        """FIPS204-STATIC-048 — Message representative is derived from the correct inputs."""
        all_code = self._all_code()
        has_pk_binding = self._contains_any(all_code, [r"tr", r"pk_hash", r"hash.*pk"])
        has_mode = self._contains_any(all_code, [r"mode", r"pure", r"prehash", r"hashml"])
        has_context = self._contains_any(all_code, [r"ctx", r"context", r"ctxlen"])
        has_message = self._contains_any(all_code, [r"message", r"msg", r"mlen"])
        if has_pk_binding and has_mode and has_context and has_message:
            return self._make_finding(
                rule_id="FIPS204-STATIC-048",
                title="Message representative is derived from the correct inputs",
                status="Passed",
                severity="Information",
                description="Signing flow includes indicators for public-key binding, mode, context, and message inputs.",
                technical_explanation=f"pk_binding={has_pk_binding}, mode={has_mode}, context={has_context}, message={has_message}",
                impact="Complete input set is required to build the standardized message representative.",
                mitigation="Keep all required components and ordering in message-representative derivation.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-048",
            title="Message representative is derived from the correct inputs",
            status="Failed",
            severity="High",
            description="Signing should derive message representative from public-key binding, mode info, context, and message/prehash input.",
            technical_explanation=f"pk_binding={has_pk_binding}, mode={has_mode}, context={has_context}, message={has_message}",
            impact="Missing input components can break challenge derivation consistency.",
            mitigation="Include all required fields in standardized order.",
        )

    def check_fips204_static_049(self) -> dict[str, Any]:
        """FIPS204-STATIC-049 — Per-signature sampling seed is derived correctly."""
        all_code = self._all_code()
        has_private_component = self._contains_any(all_code, [r"key", r"k", r"tr", r"secret"])
        has_sign_rand = self._contains_any(all_code, [r"rnd", r"random", r"rho'|rhoprime"])
        has_message_repr = self._contains_any(all_code, [r"mu", r"msg_repr", r"message representative"])
        has_seed_derivation = self._contains_any(all_code, [r"shake256", r"derive", r"expand"])
        if has_private_component and has_sign_rand and has_message_repr and has_seed_derivation:
            return self._make_finding(
                rule_id="FIPS204-STATIC-049",
                title="Per-signature sampling seed is derived correctly",
                status="Passed",
                severity="Information",
                description="Per-signature seed derivation indicators include private value, signing randomness, and message representative.",
                technical_explanation=f"private={has_private_component}, rand={has_sign_rand}, msg_repr={has_message_repr}, derive={has_seed_derivation}",
                impact="Correct seed derivation is required for standardized masking-vector sampling.",
                mitigation="Keep derivation inputs complete and ordered per specification.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-049",
            title="Per-signature sampling seed is derived correctly",
            status="Failed",
            severity="High",
            description="Sampling seed should be derived from required private value, signing randomness, and message representative.",
            technical_explanation=f"private={has_private_component}, rand={has_sign_rand}, msg_repr={has_message_repr}, derive={has_seed_derivation}",
            impact="Wrong seed derivation can produce non-conformant signatures.",
            mitigation="Implement standardized per-signature seed derivation.",
        )

    def check_fips204_static_050(self) -> dict[str, Any]:
        """FIPS204-STATIC-050 — Mask vector uses the standardized expansion."""
        all_code = self._all_code()
        has_expand_mask = self._contains_any(all_code, [r"expandmask", r"expand.*mask", r"polyvecl_uniform_gamma1", r"gamma1"])
        has_gamma1 = bool(self._extract_symbol_candidates(self.PARAM_SYMBOLS["gamma1"]))
        if has_expand_mask and has_gamma1:
            return self._make_finding(
                rule_id="FIPS204-STATIC-050",
                title="Mask vector uses the standardized expansion",
                status="Passed",
                severity="Information",
                description="Ephemeral mask/vector generation shows standardized expansion indicators with gamma1 parameter binding.",
                technical_explanation=f"has_expand_mask={has_expand_mask}, has_gamma1={has_gamma1}",
                impact="Correct mask expansion is required for conformant signing.",
                mitigation="Use standardized ExpandMask with selected gamma1.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-050",
            title="Mask vector uses the standardized expansion",
            status="Failed",
            severity="High",
            description="Ephemeral vector should be generated with standardized ExpandMask and selected gamma1.",
            technical_explanation=f"has_expand_mask={has_expand_mask}, has_gamma1={has_gamma1}",
            impact="Incorrect expansion can break rejection behavior and signature correctness.",
            mitigation="Route mask generation through standardized gamma1-bound expansion path.",
        )

    def check_fips204_static_051(self) -> dict[str, Any]:
        """FIPS204-STATIC-051 — Signing-attempt counter is advanced."""
        all_code = self._all_code()
        has_counter = self._contains_any(all_code, [r"nonce", r"counter", r"kappa"])
        increments = self._contains_any(all_code, [r"\+\+", r"\+=\s*1", r"=\s*\w+\s*\+\s*1"])
        resets_in_loop = self._contains_any(all_code, [r"while[\s\S]{0,220}counter\s*=\s*0", r"for[\s\S]{0,220}nonce\s*=\s*0"])
        if has_counter and increments and not resets_in_loop:
            return self._make_finding(
                rule_id="FIPS204-STATIC-051",
                title="Signing-attempt counter is advanced",
                status="Passed",
                severity="Information",
                description="Signing rejection-loop counter progression indicators are present without obvious in-loop reset.",
                technical_explanation=f"has_counter={has_counter}, increments={increments}, resets_in_loop={resets_in_loop}",
                impact="Counter progression prevents nonce reuse across signing attempts.",
                mitigation="Keep monotonic counter progression in rejection loop.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-051",
            title="Signing-attempt counter is advanced",
            status="Failed",
            severity="High",
            description="Rejection-loop attempts should advance counter/nonce and avoid reset/reuse patterns.",
            technical_explanation=f"has_counter={has_counter}, increments={increments}, resets_in_loop={resets_in_loop}",
            impact="Counter reuse can undermine signing correctness and conformance.",
            mitigation="Increment counter per attempt and prevent loop-local reset.",
        )

    def check_fips204_static_052(self) -> dict[str, Any]:
        """FIPS204-STATIC-052 — Commitment is calculated from the correct matrix and vector."""
        all_code = self._all_code()
        has_matrix = self._contains_any(all_code, [r"matrix", r"A", r"expand.*matrix", r"gen_matrix"])
        has_ephemeral = self._contains_any(all_code, [r"y", r"mask", r"ephemeral", r"polyvecl_uniform_gamma1"])
        has_commit = self._contains_any(all_code, [r"w1", r"commit", r"compute.*w", r"mat.*vec"])
        if has_matrix and has_ephemeral and has_commit:
            return self._make_finding(
                rule_id="FIPS204-STATIC-052",
                title="Commitment is calculated from the correct matrix and vector",
                status="Passed",
                severity="Information",
                description="Commitment calculation indicators reference expanded matrix and ephemeral masking vector.",
                technical_explanation=f"has_matrix={has_matrix}, has_ephemeral={has_ephemeral}, has_commit={has_commit}",
                impact="Correct commitment construction is required before challenge derivation.",
                mitigation="Compute commitment from expanded public matrix and ephemeral vector.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-052",
            title="Commitment is calculated from the correct matrix and vector",
            status="Failed",
            severity="High",
            description="Implementation should compute commitment from expanded public matrix and ephemeral mask vector.",
            technical_explanation=f"has_matrix={has_matrix}, has_ephemeral={has_ephemeral}, has_commit={has_commit}",
            impact="Incorrect commitment path breaks challenge binding and verification.",
            mitigation="Align commitment computation with standardized matrix-vector equation.",
        )

    def check_fips204_static_053(self) -> dict[str, Any]:
        """FIPS204-STATIC-053 — High-order coefficients are encoded correctly."""
        all_code = self._all_code()
        has_decompose = self._contains_any(all_code, [r"decompose", r"high", r"w1", r"pack_w1", r"encode.*w1"])
        has_before_challenge = bool(re.search(r"w1[\s\S]{0,250}(challenge|cseed|sampleinball)", all_code, re.IGNORECASE))
        if has_decompose and has_before_challenge:
            return self._make_finding(
                rule_id="FIPS204-STATIC-053",
                title="High-order coefficients are encoded correctly",
                status="Passed",
                severity="Information",
                description="Commitment high-order decomposition/encoding appears present before challenge derivation.",
                technical_explanation=f"has_decompose={has_decompose}, has_before_challenge={has_before_challenge}",
                impact="Correct high-order encoding is needed for standardized challenge input.",
                mitigation="Keep decomposition and encoding before challenge-seed derivation.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-053",
            title="High-order coefficients are encoded correctly",
            status="Failed",
            severity="High",
            description="Commitment should be decomposed and high-order components encoded before challenge derivation.",
            technical_explanation=f"has_decompose={has_decompose}, has_before_challenge={has_before_challenge}",
            impact="Missing or late encoding can alter challenge computation.",
            mitigation="Encode required high-order coefficients in the standardized step order.",
        )

    def check_fips204_static_054(self) -> dict[str, Any]:
        """FIPS204-STATIC-054 — Challenge seed uses the correct inputs."""
        all_code = self._all_code()
        has_mu = self._contains_any(all_code, [r"\bmu\b", r"msg_repr", r"message representative"])
        has_commitment = self._contains_any(all_code, [r"w1", r"commit", r"packed_w1"])
        has_cseed = self._contains_any(all_code, [r"cseed", r"challenge seed", r"shake.*challenge"])
        if has_mu and has_commitment and has_cseed:
            return self._make_finding(
                rule_id="FIPS204-STATIC-054",
                title="Challenge seed uses the correct inputs",
                status="Passed",
                severity="Information",
                description="Challenge-seed derivation indicators include message representative and encoded commitment.",
                technical_explanation=f"has_mu={has_mu}, has_commitment={has_commitment}, has_cseed={has_cseed}",
                impact="Correct challenge seed inputs are required for signing/verifying agreement.",
                mitigation="Derive challenge seed from message representative and encoded commitment only.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-054",
            title="Challenge seed uses the correct inputs",
            status="Failed",
            severity="High",
            description="Challenge seed should be derived from message representative and encoded commitment.",
            technical_explanation=f"has_mu={has_mu}, has_commitment={has_commitment}, has_cseed={has_cseed}",
            impact="Wrong challenge-seed inputs break signature equation consistency.",
            mitigation="Restrict challenge-seed derivation inputs to standardized fields.",
        )

    def check_fips204_static_055(self) -> dict[str, Any]:
        """FIPS204-STATIC-055 — Challenge uses SampleInBall."""
        all_code = self._all_code()
        has_sampleinball = self._contains_any(all_code, [r"sampleinball", r"poly_challenge", r"challenge.*ball"])
        if has_sampleinball:
            return self._make_finding(
                rule_id="FIPS204-STATIC-055",
                title="Challenge uses SampleInBall",
                status="Passed",
                severity="Information",
                description="Challenge-polynomial generation includes SampleInBall/poly_challenge indicators.",
                technical_explanation=f"has_sampleinball={has_sampleinball}",
                impact="Standardized challenge sampling is required for conformance.",
                mitigation="Use SampleInBall-compatible challenge generation path.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-055",
            title="Challenge uses SampleInBall",
            status="Failed",
            severity="High",
            description="Challenge polynomial should be derived using standardized SampleInBall procedure.",
            technical_explanation=f"has_sampleinball={has_sampleinball}",
            impact="Non-standard challenge sampling can invalidate signatures.",
            mitigation="Implement challenge expansion with SampleInBall procedure.",
        )

    def check_fips204_static_056(self) -> dict[str, Any]:
        """FIPS204-STATIC-056 — Response vector is calculated correctly."""
        all_code = self._all_code()
        has_response = self._contains_any(all_code, [r"\bz\b", r"response", r"compute_z", r"polyvecl_add"])
        has_y = self._contains_any(all_code, [r"\by\b", r"ephemeral", r"mask"])
        has_cs1 = self._contains_any(all_code, [r"c\s*\*\s*s1", r"challenge.*secret", r"polyvecl_pointwise_poly_montgomery"])
        if has_response and has_y and has_cs1:
            return self._make_finding(
                rule_id="FIPS204-STATIC-056",
                title="Response vector is calculated correctly",
                status="Passed",
                severity="Information",
                description="Response-vector computation indicators include ephemeral vector and challenge-times-secret term.",
                technical_explanation=f"has_response={has_response}, has_y={has_y}, has_cs1={has_cs1}",
                impact="Correct response equation is required for valid signatures.",
                mitigation="Compute response as standardized combination of y and c·s1.",
            )
        return self._make_finding(
            rule_id="FIPS204-STATIC-056",
            title="Response vector is calculated correctly",
            status="Failed",
            severity="High",
            description="Response vector should combine ephemeral vector and challenge-times-secret vector using required signing equation.",
            technical_explanation=f"has_response={has_response}, has_y={has_y}, has_cs1={has_cs1}",
            impact="Incorrect response equation causes invalid/non-interoperable signatures.",
            mitigation="Implement standardized response-vector calculation path.",
        )
