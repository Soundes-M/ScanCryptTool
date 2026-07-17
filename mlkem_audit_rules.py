from __future__ import annotations

import re
from pathlib import Path
from typing import Any


class MLKEMAuditRules:
    """ML-KEM (Kyber) static auditing rules (FIPS 203)."""

    PARAM_SETS = {
        "ML-KEM-512": {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4},
        "ML-KEM-768": {"k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4},
        "ML-KEM-1024": {"k": 4, "eta1": 2, "eta2": 2, "du": 11, "dv": 5},
    }

    SYMBOLS = {
        "n": ["KYBER_N", "ML_KEM_N", "N"],
        "q": ["KYBER_Q", "ML_KEM_Q", "Q"],
        "k": ["KYBER_K", "ML_KEM_K", "K"],
        "eta1": ["KYBER_ETA1", "ML_KEM_ETA1", "ETA1"],
        "eta2": ["KYBER_ETA2", "ML_KEM_ETA2", "ETA2"],
        "du": ["KYBER_DU", "ML_KEM_DU", "DU"],
        "dv": ["KYBER_DV", "ML_KEM_DV", "DV"],
        "seed_bytes": ["KYBER_SYMBYTES", "SYMBYTES", "SEEDBYTES", "ML_KEM_SEEDBYTES"],
    }

    def __init__(self, all_files: list[tuple[str, str]]):
        self.all_files = all_files

    def run(self) -> list[dict[str, Any]]:
        return [
            self.check_fips203_static_005(),
            self.check_fips203_static_006(),
            self.check_fips203_static_007(),
            self.check_fips203_static_008(),
            self.check_fips203_static_009(),
            self.check_fips203_static_010(),
            self.check_fips203_static_011(),
            self.check_fips203_static_012(),
            self.check_fips203_static_013(),
            self.check_fips203_static_014(),
            self.check_fips203_static_015(),
            self.check_fips203_static_016(),
            self.check_fips203_static_017(),
            self.check_fips203_static_018(),
            self.check_fips203_static_019(),
            self.check_fips203_static_020(),
            self.check_fips203_static_021(),
            self.check_fips203_static_022(),
            self.check_fips203_static_023(),
            self.check_fips203_static_024(),
            self.check_fips203_static_025(),
            self.check_fips203_static_026(),
            self.check_fips203_static_027(),
            self.check_fips203_static_028(),
            self.check_fips203_static_029(),
            self.check_fips203_static_030(),
            self.check_fips203_static_031(),
            self.check_fips203_static_032(),
            self.check_fips203_static_033(),
            self.check_fips203_static_034(),
            self.check_fips203_static_035(),
            self.check_fips203_static_036(),
            self.check_fips203_static_037(),
            self.check_fips203_static_038(),
            self.check_fips203_static_039(),
            self.check_fips203_static_040(),
            self.check_fips203_static_041(),
            self.check_fips203_static_042(),
            self.check_fips203_static_043(),
            self.check_fips203_static_044(),
            self.check_fips203_static_045(),
            self.check_fips203_static_046(),
            self.check_fips203_static_047(),
            self.check_fips203_static_048(),
            self.check_fips203_static_049(),
            self.check_fips203_static_050(),
            self.check_fips203_static_051(),
            self.check_fips203_static_052(),
            self.check_fips203_static_053(),
            self.check_fips203_static_054(),
            self.check_fips203_static_055(),
            self.check_fips203_static_056(),
            self.check_fips203_static_057(),
            self.check_fips203_static_058(),
            self.check_fips203_static_059(),
            self.check_fips203_static_060(),
        ]

    def _all_code(self) -> str:
        return "\n".join(code for _, code in self.all_files)

    @staticmethod
    def _parse_int_literal(expr: str | None) -> int | None:
        if not expr:
            return None
        token = expr.strip().split("//", 1)[0].strip()
        m = re.match(r"^([+-]?(?:0[xX][0-9A-Fa-f]+|\d+))(?:[uUlL]+)?$", token)
        if not m:
            return None
        try:
            return int(m.group(1), 0)
        except Exception:
            return None

    def _extract_symbol_candidates(self, symbols: list[str]) -> list[tuple[str, int, str, int]]:
        out: list[tuple[str, int, str, int]] = []
        for file_path, code in self.all_files:
            for symbol in symbols:
                esc = re.escape(symbol)
                pats = [
                    rf"^\s*#\s*define\s+{esc}\s+([^\n/]+)",
                    rf"\b(?:const\s+)?(?:static\s+)?(?:unsigned\s+|signed\s+)?(?:short\s+|long\s+)?(?:int|int32_t|uint32_t|int64_t|uint64_t)\s+{esc}\s*=\s*([^;\n]+)",
                ]
                for pat in pats:
                    for m in re.finditer(pat, code, re.MULTILINE):
                        v = self._parse_int_literal(m.group(1))
                        if v is None:
                            continue
                        line = code.count("\n", 0, m.start()) + 1
                        out.append((file_path, line, symbol, v))
        return out

    @staticmethod
    def _contains_any(code: str, patterns: list[str]) -> bool:
        return any(re.search(p, code, re.IGNORECASE) for p in patterns)

    @staticmethod
    def _make(rule_id: str, title: str, status: str, severity: str, description: str, technical: str, impact: str, mitigation: str, file: str = "-", line: int | str = "-") -> dict[str, Any]:
        return {
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "category": "FIPS 203 / Static",
            "status": status,
            "affected_algorithm": "ML-KEM",
            "file": file,
            "line": line,
            "description": description,
            "impact": impact,
            "technical_explanation": technical,
            "mitigation": mitigation,
            "references": ["NIST FIPS 203"],
        }

    def _selected_set(self) -> str | None:
        vals = [x[3] for x in self._extract_symbol_candidates(self.SYMBOLS["k"])]
        if 2 in vals:
            return "ML-KEM-512"
        if 3 in vals:
            return "ML-KEM-768"
        if 4 in vals:
            return "ML-KEM-1024"
        all_code = self._all_code()
        if re.search(r"ML_KEM_512|kyber512", all_code, re.IGNORECASE):
            return "ML-KEM-512"
        if re.search(r"ML_KEM_768|kyber768", all_code, re.IGNORECASE):
            return "ML-KEM-768"
        if re.search(r"ML_KEM_1024|kyber1024", all_code, re.IGNORECASE):
            return "ML-KEM-1024"
        return None

    def _check_exact(self, rule_id: str, title: str, symbols: list[str], expected: int, desc: str) -> dict[str, Any]:
        cands = self._extract_symbol_candidates(symbols)
        ok = [c for c in cands if c[3] == expected]
        bad = [c for c in cands if c[3] != expected]
        if ok:
            f, l, s, v = ok[0]
            return self._make(rule_id, title, "Passed", "Information", desc, f"Detected {s}={v}.", "Wrong constants break conformance.", "Keep constants exact per FIPS 203.", Path(f).name, l)
        if bad:
            f, l, s, v = bad[0]
            return self._make(rule_id, title, "Failed", "High", desc, f"Detected {s}={v}; expected {expected}.", "Wrong constants break conformance.", "Fix the constant to required value.", Path(f).name, l)
        return self._make(rule_id, title, "Failed", "Medium", desc, "No extractable constant found.", "Cannot verify conformance.", "Define/export the required constant.")

    def _check_set_param(self, rule_id: str, title: str, param_key: str, symbols: list[str]) -> dict[str, Any]:
        sel = self._selected_set()
        if not sel:
            return self._make(rule_id, title, "Failed", "Medium", f"Verify {param_key} for selected parameter set.", "Parameter set not identified.", "Cannot verify set-specific constants.", "Expose KYBER_K / ML_KEM_* identifiers.")
        expected = self.PARAM_SETS[sel][param_key]
        return self._check_exact(rule_id, title, symbols, expected, f"Verify {param_key} for {sel}.")

    def _pattern_rule(self, rule_id: str, title: str, required: list[str], description: str, forbidden: list[str] | None = None) -> dict[str, Any]:
        code = self._all_code()
        ok = self._contains_any(code, required)
        bad = self._contains_any(code, forbidden or [])
        if ok and not bad:
            return self._make(rule_id, title, "Passed", "Information", description, "Required indicators found.", "Missing flow can break conformance.", "Keep standardized implementation path.")
        return self._make(rule_id, title, "Failed", "High" if bad else "Medium", description, f"required_found={ok}, forbidden_found={bad}", "Potential non-conformance.", "Implement standardized flow and remove unsupported alternatives.")

    # Parameters
    def check_fips203_static_005(self): return self._check_exact("FIPS203-STATIC-005", "Polynomial degree is correct", self.SYMBOLS["n"], 256, "Verify polynomial degree n = 256.")
    def check_fips203_static_006(self): return self._check_exact("FIPS203-STATIC-006", "Modulus is correct", self.SYMBOLS["q"], 3329, "Verify modulus q = 3329.")
    def check_fips203_static_007(self): return self._check_set_param("FIPS203-STATIC-007", "Parameter k is correct", "k", self.SYMBOLS["k"])
    def check_fips203_static_008(self): return self._check_set_param("FIPS203-STATIC-008", "Parameter eta1 is correct", "eta1", self.SYMBOLS["eta1"])
    def check_fips203_static_009(self): return self._check_set_param("FIPS203-STATIC-009", "Parameter eta2 is correct", "eta2", self.SYMBOLS["eta2"])
    def check_fips203_static_010(self): return self._check_set_param("FIPS203-STATIC-010", "Parameter du is correct", "du", self.SYMBOLS["du"])
    def check_fips203_static_011(self): return self._check_set_param("FIPS203-STATIC-011", "Parameter dv is correct", "dv", self.SYMBOLS["dv"])

    def check_fips203_static_012(self):
        return self._pattern_rule("FIPS203-STATIC-012", "Compression constants are correct", [r"poly_compress", r"polyvec_compress", r"KYBER_DU", r"KYBER_DV"], "Verify compression constants.")

    def check_fips203_static_013(self):
        return self._pattern_rule("FIPS203-STATIC-013", "Polynomial dimensions are correct", [r"\[\s*256\s*\]", r"KYBER_N", r"for\s*\([^;]*<\s*(?:KYBER_N|256)"], "Verify polynomial dimensions.")

    def check_fips203_static_014(self):
        return self._pattern_rule("FIPS203-STATIC-014", "Matrix dimensions are correct", [r"gen_matrix", r"for\s*\([^;]*<\s*(?:KYBER_K|[234])", r"polyvec_matrix"], "Verify matrix dimensions.")

    # Hash / XOF
    def check_fips203_static_015(self): return self._pattern_rule("FIPS203-STATIC-015", "SHAKE128 usage is correct", [r"shake128"], "Verify SHAKE128 usage.")
    def check_fips203_static_016(self): return self._pattern_rule("FIPS203-STATIC-016", "SHAKE256 usage is correct", [r"shake256"], "Verify SHAKE256 usage.")
    def check_fips203_static_017(self): return self._pattern_rule("FIPS203-STATIC-017", "SHA3-256 usage is correct", [r"sha3[-_]?256", r"sha3_256"], "Verify SHA3-256 usage.")
    def check_fips203_static_018(self): return self._pattern_rule("FIPS203-STATIC-018", "SHA3-512 usage is correct", [r"sha3[-_]?512", r"sha3_512"], "Verify SHA3-512 usage.")

    def check_fips203_static_019(self):
        return self._pattern_rule(
            "FIPS203-STATIC-019",
            "Unsupported hash substitutions are rejected",
            [r"shake128|shake256|sha3"],
            "Reject unsupported hash substitutions.",
            forbidden=[r"md5", r"blake2", r"blake3", r"sha1"],
        )

    def check_fips203_static_020(self): return self._pattern_rule("FIPS203-STATIC-020", "Required output lengths are used", [r"shake(?:128|256)\s*\([^\)]*(?:len|BYTES|\d+)"], "Verify required output lengths.")
    def check_fips203_static_021(self): return self._pattern_rule("FIPS203-STATIC-021", "Domain separation is implemented", [r"nonce", r"domain", r"absorb"], "Verify domain separation.")

    # Key generation
    def check_fips203_static_022(self):
        seed = self._extract_symbol_candidates(self.SYMBOLS["seed_bytes"])
        has32 = any(v == 32 for _, _, _, v in seed)
        return self._make("FIPS203-STATIC-022", "Seed length is correct", "Passed" if has32 else "Failed", "Information" if has32 else "High", "Verify seed length.", f"seed32={has32}", "Wrong seed length breaks keygen conformance.", "Use 32-byte seed input.")

    def check_fips203_static_023(self): return self._pattern_rule("FIPS203-STATIC-023", "Matrix expansion is correct", [r"gen_matrix", r"expand.*matrix", r"KYBER_K"], "Verify matrix expansion.")
    def check_fips203_static_024(self): return self._pattern_rule("FIPS203-STATIC-024", "CBD sampling is correct", [r"cbd2", r"cbd3", r"eta"], "Verify CBD sampling.")
    def check_fips203_static_025(self): return self._pattern_rule("FIPS203-STATIC-025", "Secret vector dimensions are correct", [r"polyvec", r"KYBER_K", r"\[\s*KYBER_K\s*\]"], "Verify secret vector dimensions.")
    def check_fips203_static_026(self): return self._pattern_rule("FIPS203-STATIC-026", "Error vector dimensions are correct", [r"e1|e2", r"polyvec", r"KYBER_K"], "Verify error vector dimensions.")
    def check_fips203_static_027(self): return self._pattern_rule("FIPS203-STATIC-027", "Public-key construction is correct", [r"pack_pk", r"indcpa_keypair"], "Verify public-key construction.")
    def check_fips203_static_028(self): return self._pattern_rule("FIPS203-STATIC-028", "Secret-key construction is correct", [r"pack_sk", r"indcpa_keypair"], "Verify secret-key construction.")
    def check_fips203_static_029(self): return self._pattern_rule("FIPS203-STATIC-029", "hash(pk) inclusion is correct", [r"hash.*pk", r"hpk", r"sha3_256"], "Verify hash(pk) inclusion.")
    def check_fips203_static_030(self): return self._pattern_rule("FIPS203-STATIC-030", "Secret-key field ordering is correct", [r"pack_sk", r"rho", r"pk", r"hpk"], "Verify secret key field ordering.")

    # Encapsulation
    def check_fips203_static_031(self): return self._pattern_rule("FIPS203-STATIC-031", "Encapsulation randomness length is correct", [r"coins", r"randombytes\s*\([^\)]*,\s*32\s*\)", r"KYBER_SYMBYTES"], "Verify randomness length.")
    def check_fips203_static_032(self): return self._pattern_rule("FIPS203-STATIC-032", "Message generation is correct", [r"m\[", r"indcpa_enc", r"hash"], "Verify message generation.")
    def check_fips203_static_033(self): return self._pattern_rule("FIPS203-STATIC-033", "Encryption seed derivation is correct", [r"coins", r"kr", r"hash"], "Verify encryption seed derivation.")
    def check_fips203_static_034(self): return self._pattern_rule("FIPS203-STATIC-034", "Challenge generation is correct", [r"hash_g", r"sha3_512", r"kr"], "Verify challenge generation.")
    def check_fips203_static_035(self): return self._pattern_rule("FIPS203-STATIC-035", "Polynomial encoding is correct", [r"poly_tobytes", r"poly_frombytes"], "Verify polynomial encoding.")
    def check_fips203_static_036(self): return self._pattern_rule("FIPS203-STATIC-036", "Ciphertext construction is correct", [r"pack_ciphertext", r"indcpa_enc"], "Verify ciphertext construction.")
    def check_fips203_static_037(self): return self._pattern_rule("FIPS203-STATIC-037", "Ciphertext field ordering is correct", [r"pack_ciphertext\s*\([^\)]*u[^\)]*v"], "Verify ciphertext field ordering.")
    def check_fips203_static_038(self): return self._pattern_rule("FIPS203-STATIC-038", "Ciphertext compression is correct", [r"polyvec_compress", r"poly_compress"], "Verify ciphertext compression.")

    # Decapsulation
    def check_fips203_static_039(self): return self._pattern_rule("FIPS203-STATIC-039", "Ciphertext decoding is correct", [r"unpack_ciphertext", r"indcpa_dec"], "Verify ciphertext decoding.")
    def check_fips203_static_040(self): return self._pattern_rule("FIPS203-STATIC-040", "Ciphertext decompression is correct", [r"polyvec_decompress", r"poly_decompress"], "Verify ciphertext decompression.")
    def check_fips203_static_041(self): return self._pattern_rule("FIPS203-STATIC-041", "Secret-key decoding is correct", [r"unpack_sk", r"indcpa_dec"], "Verify secret-key decoding.")
    def check_fips203_static_042(self): return self._pattern_rule("FIPS203-STATIC-042", "Ciphertext recomputation is correct", [r"indcpa_enc", r"cmp", r"verify"], "Verify recomputation of ciphertext.")
    def check_fips203_static_043(self): return self._pattern_rule("FIPS203-STATIC-043", "Implicit rejection logic is correct", [r"cmov", r"verify", r"fail"], "Verify implicit rejection logic.")
    def check_fips203_static_044(self): return self._pattern_rule("FIPS203-STATIC-044", "Shared-secret derivation is correct", [r"kdf", r"ss", r"shake256"], "Verify shared-secret derivation.")
    def check_fips203_static_045(self): return self._pattern_rule("FIPS203-STATIC-045", "Comparison against recomputed ciphertext is correct", [r"verify\s*\(", r"memcmp", r"ct"], "Verify comparison against recomputed ciphertext.")

    # NTT operations
    def check_fips203_static_046(self): return self._pattern_rule("FIPS203-STATIC-046", "Forward NTT is implemented", [r"\bntt\b"], "Verify forward NTT implementation.")
    def check_fips203_static_047(self): return self._pattern_rule("FIPS203-STATIC-047", "Inverse NTT is implemented", [r"invntt", r"inv_ntt"], "Verify inverse NTT implementation.")
    def check_fips203_static_048(self): return self._pattern_rule("FIPS203-STATIC-048", "Montgomery reduction is implemented", [r"montgomery_reduce"], "Verify Montgomery reduction.")
    def check_fips203_static_049(self): return self._pattern_rule("FIPS203-STATIC-049", "Barrett reduction is implemented", [r"barrett_reduce"], "Verify Barrett reduction.")
    def check_fips203_static_050(self): return self._pattern_rule("FIPS203-STATIC-050", "NTT constants are present", [r"zetas", r"KYBER_Q"], "Verify NTT constants.")
    def check_fips203_static_051(self): return self._pattern_rule("FIPS203-STATIC-051", "Twiddle factors are present", [r"zetas", r"omega", r"twiddle"], "Verify twiddle factors.")
    def check_fips203_static_052(self): return self._pattern_rule("FIPS203-STATIC-052", "Polynomial multiplication flow is correct", [r"basemul", r"pointwise", r"ntt"], "Verify polynomial multiplication flow.")

    # Encoding / compression
    def check_fips203_static_053(self): return self._pattern_rule("FIPS203-STATIC-053", "Coefficient packing is correct", [r"<<", r">>", r"mask", r"pack"], "Verify coefficient packing.")
    def check_fips203_static_054(self): return self._pattern_rule("FIPS203-STATIC-054", "Polynomial packing is correct", [r"poly_tobytes", r"poly_frombytes"], "Verify polynomial packing.")
    def check_fips203_static_055(self): return self._pattern_rule("FIPS203-STATIC-055", "Public-key encoding is correct", [r"pack_pk"], "Verify public-key encoding.")
    def check_fips203_static_056(self): return self._pattern_rule("FIPS203-STATIC-056", "Secret-key encoding is correct", [r"pack_sk"], "Verify secret-key encoding.")
    def check_fips203_static_057(self): return self._pattern_rule("FIPS203-STATIC-057", "Ciphertext encoding is correct", [r"pack_ciphertext"], "Verify ciphertext encoding.")
    def check_fips203_static_058(self): return self._pattern_rule("FIPS203-STATIC-058", "Endian handling is correct", [r"little", r"load32", r"store32", r"to_bytes"], "Verify endian correctness.")
    def check_fips203_static_059(self): return self._pattern_rule("FIPS203-STATIC-059", "Bit widths are correct", [r"\b10\b|\b11\b|\b4\b|\b5\b", r"mask", r"shift"], "Verify bit widths.")
    def check_fips203_static_060(self): return self._pattern_rule("FIPS203-STATIC-060", "Compression formulas are correct", [r"compress", r"decompress", r"KYBER_Q", r"DU|DV"], "Verify compression formulas.")
