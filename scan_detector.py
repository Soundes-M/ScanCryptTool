import os
import re
import json
from pathlib import Path

SUPPORTED_EXTS = {".c", ".h", ".cpp", ".cc", ".hpp", ".S", ".s", ".asm"}
SUPPORTED_NAMES = {"cmakelists.txt", "makefile"}


def parse_integer_parameter(code: str, name: str):
    patterns = [
        rf"#define\s+{name}\s+(\d+)",
        rf"\bconst\s+int\s+{name}\s*=\s*(\d+)",
        rf"\bint\s+{name}\s*=\s*(\d+)",
        rf"\b{name}\b\s*=\s*(\d+)",
    ]
    for p in patterns:
        m = re.search(p, code)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                continue
    return None


FAMILY_INDICATORS = {
    "dilithium": {
        "strong": [
            r"poly_challenge", r"polyvecl", r"polyveck", r"make_hint", r"use_hint",
            r"decompose", r"rej_uniform", r"DILITHIUM_MODE", r"DILITHIUM2", r"DILITHIUM3",
            r"DILITHIUM5", r"ML_DSA_44", r"ML_DSA_65", r"ML_DSA_87", r"CRYPTO_ALGNAME",
        ],
        "medium": [r"\bpoly\b", r"small_noise", r"\bNTT\b"],
    },
    "kyber": {
        "strong": [
            r"KYBER_K", r"KYBER_Q", r"KYBER_N", r"KYBER_ETA1", r"KYBER_ETA2",
            r"indcpa_keypair", r"indcpa_enc", r"indcpa_dec", r"gen_matrix",
            r"polyvec_compress", r"polyvec_decompress", r"poly_compress", r"poly_decompress",
            r"pack_pk", r"pack_sk", r"pack_ciphertext", r"unpack_ciphertext",
            r"cbd2", r"cbd3", r"ML_KEM_512", r"ML_KEM_768", r"ML_KEM_1024",
            r"kyber512", r"kyber768", r"kyber1024",
        ],
        "medium": [r"ntt", r"invntt", r"montgomery_reduce", r"barrett_reduce"],
    },
    "shake": {
        "weak": [r"shake128", r"shake256", r"fips202", r"keccak", r"sha3"],
    },
}

IMPLEMENTATION_INDICATORS = {
    "AVX2 Optimized": [r"avx2", r"__m256i", r"immintrin\.h", r"__AVX2__", r"immintrin"],
    "ARM Cortex-M/Embedded": [r"cortex-m", r"\bm4\b", r"stm32", r"\.thumb", r"cmsis", r"__ARM_ARCH"],
    "Masked Implementation": [r"\bmasked\b", r"\bmask\b", r"\bshare(s)?\b", r"NSHARES", r"\bORDER\b", r"refresh"],
    "Hardware/FPGA": [r"\.v$", r"\.sv$", r"module\b", r"assign\b", r"always\b", r"entity\b"],
}


def score_family(code: str):
    scores = {"dilithium": 0, "kyber": 0, "shake": 0}
    matches = {"dilithium": [], "kyber": [], "shake": []}

    # Dilithium
    for pat in FAMILY_INDICATORS["dilithium"]["strong"]:
        if re.search(pat, code, re.IGNORECASE):
            scores["dilithium"] += 5
            matches["dilithium"].append(pat)
    for pat in FAMILY_INDICATORS["dilithium"].get("medium", []):
        if re.search(pat, code, re.IGNORECASE):
            scores["dilithium"] += 3
            matches["dilithium"].append(pat)

    # Kyber
    for pat in FAMILY_INDICATORS["kyber"]["strong"]:
        if re.search(pat, code, re.IGNORECASE):
            scores["kyber"] += 5
            matches["kyber"].append(pat)
    for pat in FAMILY_INDICATORS["kyber"].get("medium", []):
        if re.search(pat, code, re.IGNORECASE):
            scores["kyber"] += 3
            matches["kyber"].append(pat)

    # SHAKE (weak)
    for pat in FAMILY_INDICATORS["shake"].get("weak", []):
        if re.search(pat, code, re.IGNORECASE):
            scores["shake"] += 1
            matches["shake"].append(pat)

    return scores, matches


def detect_implementation_type(all_codes):
    # all_codes: list of (filename, code)
    impl_scores = {k: 0 for k in IMPLEMENTATION_INDICATORS}
    evidence = []
    for fname, code in all_codes:
        for impl, pats in IMPLEMENTATION_INDICATORS.items():
            for pat in pats:
                if re.search(pat, code, re.IGNORECASE):
                    impl_scores[impl] += 5
                    evidence.append((impl, pat, fname))

    if not impl_scores:
        return "Portable C / Reference", []

    best = max(impl_scores.items(), key=lambda x: x[1])
    if best[1] == 0:
        return "Portable C / Reference", []
    return best[0], evidence


def analyze_project(path: str):
    path = Path(path)
    all_files = []
    total_loc = 0
    c_count = 0
    h_count = 0
    file_count = 0
    build_cmake = False
    build_make = False

    family_scores = {"dilithium": 0, "kyber": 0, "shake": 0}
    family_matches = {"dilithium": [], "kyber": [], "shake": []}
    matched_params = {}
    file_evidence = []

    for root, dirs, files in os.walk(path):
        for fname in files:
            lname = fname.lower()
            suffix = Path(fname).suffix
            if suffix in SUPPORTED_EXTS or lname in SUPPORTED_NAMES:
                file_count += 1
                fpath = Path(root) / fname
                try:
                    code = fpath.read_text(errors='ignore')
                except Exception:
                    continue
                loc = code.count('\n') + 1
                total_loc += loc
                all_files.append((str(fpath), code))
                if suffix == ".h":
                    h_count += 1
                if suffix in {".c", ".cpp", ".cc", ".S", ".s", ".asm", ".hpp"}:
                    c_count += 1
                if lname == "cmakelists.txt":
                    build_cmake = True
                if lname == "makefile":
                    build_make = True

                # per-file scoring
                scores, matches = score_family(code)
                for k in family_scores:
                    family_scores[k] += scores.get(k, 0)
                    family_matches[k].extend(matches.get(k, []))

                # parse params
                for p in ("K", "L", "ETA", "GAMMA1", "GAMMA2"):
                    v = parse_integer_parameter(code, p)
                    if v is not None:
                        matched_params[p] = v
                for p in ("KYBER_K", "KYBER_ETA1", "DU", "DV"):
                    v = parse_integer_parameter(code, p)
                    if v is not None:
                        matched_params[p] = v

                # record evidence
                for patlist in matches.values():
                    for pat in patlist:
                        file_evidence.append((fname, pat))

    # Determine build system
    build_system = "CMake" if build_cmake else ("Make" if build_make else "Unknown")

    # Implementation type
    implementation_type, impl_evidence = detect_implementation_type(all_files)

    # Crypto primitives (SHAKE)
    crypto_primitives = []
    for fname, code in all_files:
        for pat in FAMILY_INDICATORS["shake"]["weak"]:
            if re.search(pat, code, re.IGNORECASE):
                val = pat.replace('\\b','').upper()
                if 'SHAKE256' not in crypto_primitives and re.search(r'shake256', code, re.IGNORECASE):
                    crypto_primitives.append('SHAKE256')
                if 'SHAKE128' not in crypto_primitives and re.search(r'shake128', code, re.IGNORECASE):
                    crypto_primitives.append('SHAKE128')

    # Decide algorithm: prefer dilithium/kyber using family_scores and thresholds
    chosen = "Unknown"
    chosen_family = None
    threshold = 8
    # prefer dilithium first if tied
    if family_scores["dilithium"] >= threshold or family_scores["kyber"] >= threshold:
        if family_scores["dilithium"] >= family_scores["kyber"]:
            chosen = "ML-DSA / Dilithium"
            chosen_family = "dilithium"
        else:
            chosen = "ML-KEM / Kyber"
            chosen_family = "kyber"
    else:
        # no family strong enough; don't return SHA-3 as main algorithm
        chosen = "Unknown"

    # Security level inference
    security_level = "Unknown"
    # Dilithium rules
    if chosen_family == "dilithium":
        if (matched_params.get('K') == 4 and matched_params.get('L') == 4) or re.search(r'DILITHIUM2|ML_DSA_44', ' '.join(f for f,_ in all_files), re.IGNORECASE):
            security_level = "ML-DSA-44 / Dilithium2"
        elif (matched_params.get('K') == 6 and matched_params.get('L') == 5) or re.search(r'DILITHIUM3|ML_DSA_65', ' '.join(f for f,_ in all_files), re.IGNORECASE):
            security_level = "ML-DSA-65 / Dilithium3"
        elif (matched_params.get('K') == 8 and matched_params.get('L') == 7) or re.search(r'DILITHIUM5|ML_DSA_87', ' '.join(f for f,_ in all_files), re.IGNORECASE):
            security_level = "ML-DSA-87 / Dilithium5"
        else:
            security_level = "Unknown Dilithium Variant"

    if chosen_family == "kyber":
        ky_k = matched_params.get('KYBER_K') or matched_params.get('K')
        if ky_k == 2 or re.search(r'kyber512|ML_KEM_512', ' '.join(f for f,_ in all_files), re.IGNORECASE):
            security_level = "ML-KEM-512 / Kyber512"
        elif ky_k == 3 or re.search(r'kyber768|ML_KEM_768', ' '.join(f for f,_ in all_files), re.IGNORECASE):
            security_level = "ML-KEM-768 / Kyber768"
        elif ky_k == 4 or re.search(r'kyber1024|ML_KEM_1024', ' '.join(f for f,_ in all_files), re.IGNORECASE):
            security_level = "ML-KEM-1024 / Kyber1024"
        else:
            security_level = "Unknown ML-KEM Variant"

    # Confidence calculation
    base = 40
    family_score = family_scores.get(chosen_family, 0) if chosen_family else 0
    confidence = base + family_score * 5
    if security_level and "unknown" not in security_level.lower():
        confidence += 10
    # corroboration: count files with at least one match
    corroborating_files = 0
    for fname, code in all_files:
        sc, _ = score_family(code)
        if sc.get(chosen_family, 0) > 0:
            corroborating_files += 1
    if corroborating_files > 1:
        confidence += 5
    if confidence > 99:
        confidence = 99

    # Build detection evidence with friendly labels
    def friendly_label_for_pattern(pat: str) -> str:
        p = pat.lower()
        if "kyber_k" in p:
            return "KYBER_K"
        if "kyber_n" in p:
            return "KYBER_N"
        if "kyber_q" in p:
            return "KYBER_Q"
        if "poly_challenge" in p or "polyvecl" in p or "polyveck" in p:
            return "Polynomial arithmetic"
        if "poly_compress" in p or "poly_decompress" in p or "polyvec" in p:
            return "Poly compression/decompression routines"
        if "ntt" in p or "invntt" in p:
            return "NTT implementation"
        if "indcpa_" in p:
            return "IND-CPA primitives"
        if "cbd2" in p or "cbd3" in p:
            return "Centered binomial distribution (CBD)"
        if "shake" in p or "sha3" in p or "keccak" in p:
            return "SHAKE / SHA-3 primitive"
        # fallback: strip common regex markers
        clean = re.sub(r"\\b|\\\\|\^|\$|\(|\)|\[|\]|\?|\+|\\s|\.|\*", "", pat)
        clean = clean.strip()
        return clean or pat

    algorithm_evidence = []
    impl_evidence_list = []
    seen = set()

    for fname, pat in file_evidence:
        label = friendly_label_for_pattern(pat)
        text = f"{label} detected in {fname}"
        if text not in seen:
            algorithm_evidence.append(text)
            seen.add(text)

    # parameters
    for k, v in matched_params.items():
        if v is not None:
            text = f"{k} = {v}"
        else:
            text = f"{k} detected (value not extracted)"
        if text not in seen:
            algorithm_evidence.append(text)
            seen.add(text)

    # implementation evidence
    seen_impl = set()
    for impl, pat, fname in impl_evidence:
        # friendly impl label
        impl_label = impl
        text = f"{impl_label} indicators detected in {fname}"
        if text not in seen_impl:
            impl_evidence_list.append(text)
            seen_impl.add(text)

    # Missing information reasons
    missing_information = []
    if chosen_family == "kyber":
        # if KYBER_K pattern was matched but value missing
        ky_found = any('KYBER_K' in pat.upper() or 'KYBER_K' in pat for _, pat in file_evidence)
        if ky_found and 'KYBER_K' not in matched_params:
            missing_information.append("KYBER_K was detected, but its value could not be extracted.")
    if build_system == "Unknown":
        missing_information.append("Build system not detected")

    result = {
        "algorithm": chosen,
        "crypto_primitives": crypto_primitives,
        "security_level": security_level,
        "implementation_type": implementation_type,
        "programming_language": "C/C++",
        "files": file_count,
        "c_source_files": c_count,
        "header_files": h_count,
        "lines_of_code": total_loc,
        "build_system": build_system,
        "analysis_confidence": f"{int(confidence)}%",
        "algorithm_evidence": algorithm_evidence,
        "implementation_evidence": impl_evidence_list,
        "missing_information": missing_information,
    }

    return result


if __name__ == "__main__":
    # small self-test using temporary files
    import tempfile
    td = tempfile.mkdtemp(prefix="scancrypt_test_")
    # create a tiny Dilithium-like file
    dfile = Path(td) / "dil.c"
    dfile.write_text("""
    #define K 6
    #define L 5
    void poly_challenge() {}
    void make_hint() {}
    """)
    # create a tiny Kyber-like file
    kfile = Path(td) / "k.c"
    kfile.write_text("""
    #define KYBER_K 3
    void indcpa_enc() {}
    void polyvec_compress() {}
    """)
    print(json.dumps(analyze_project(td), indent=2))
