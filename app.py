from pathlib import Path
import re
import os
import tempfile
import subprocess
import shutil
from uuid import uuid4
from datetime import datetime
from scan_detector import analyze_project
from report_generator import generate_scan_report
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
app.secret_key = "replace-with-a-secure-random-key"

# Logo upload settings
UPLOAD_FOLDER = Path(__file__).parent / "static" / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
REPORTS_FOLDER = Path(__file__).parent / "static" / "reports"
REPORTS_FOLDER.mkdir(parents=True, exist_ok=True)
ASSEMBLY_OUTPUT_FOLDER = REPORTS_FOLDER / "assembly"
ASSEMBLY_OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"}

SUPPORTED_TARGETS = {
    "cortex-m0": {"label": "ARM Cortex-M0", "mcpu": "cortex-m0"},
    "cortex-m3": {"label": "ARM Cortex-M3", "mcpu": "cortex-m3"},
    "cortex-m4": {"label": "ARM Cortex-M4", "mcpu": "cortex-m4"},
}

SUPPORTED_C_SUBSET = [
    "Function-level C routines (single translation unit input)",
    "Integer/pointer arithmetic and control flow in C/C++ source",
    "Patterns aligned with embedded ARM Cortex-M oriented code generation",
    "Code that can be represented in the executable's current IR/SSA workflow",
]

FLOW_STEPS = [
    "C input",
    "Input validation",
    "Supported operation detection",
    "Architecture selection",
    "Generator execution",
    "Generated code",
    "Warnings and assumptions",
    "Downloadable output",
]


def allowed_image(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_IMAGE_EXTENSIONS


def get_logo_filename() -> str | None:
    for p in UPLOAD_FOLDER.glob("company_logo.*"):
        return p.name
    return None


# Simple translation map for English and German
TRANSLATIONS = {
    "en": {
        "title": "ScanCrypt — Post-Quantum Security",
        "tagline": "Post-Quantum Security",
        "nav_services": "Services",
        "nav_news": "Try Me",
        "nav_about": "About",
        "nav_pricing": "Pricing",
        "nav_contact": "Contact",
        "cta_start": "Start for Free",
        "cta_demo": "Book a demo",
        "landing_h1": "Scan post-quantum cryptography for a secure future",
        "landing_lead": "Secure your ML-DSA and ML-KEM implementations. Detect side-channel, fault injection, and implementation vulnerabilities automatically.",
        "supports_title": "Supports:",
        "supports_list": ["Portable C", "ARM Cortex-M", "Embedded Firmware", "Linux", "Windows"],
        "index_title": "ScanCrypt Tool",
        "tool_title": "ScanCrypt Tool",
        "tool_description": "Select a folder of local source files and analyze every supported C/C++ file inside.",
        "upload_label": "Upload folder",
        "upload_hint": "Use a supported browser to select a folder. All files inside the folder will be processed.",
        "analyze_button": "Analyze folder",
        "analysis_complete": "Analysis complete",
        "folder_label": "Folder:",
        "files_analyzed": "Files analyzed:",
        "unsupported_ignored": "Unsupported ignored:",
        "overall_algorithm": "Algorithm",
        "overall_security_level": "Security level",
        "overall_implementation_type": "Implementation type",
        "assembly_title": "ScanCrypt — Secure Assembly Generator",
        "assembly_h1": "Secure Assembly Generation",
        "assembly_lead": "This secure code generation flow accepts C/C++ routines, processes them through an SSA-style intermediate form, derives parameter and call security context, performs taint tracking across basic blocks, and emits hardened assembly output with protection-focused transformations. The current generation profile targets embedded ARM Cortex-M class platforms (ARMv6-M style output), making it suitable for constrained firmware environments.",
        "assembly_input_title": "Input C source",
        "assembly_input_help": "Paste C code below or upload a C/C++ file.",
        "assembly_upload_label": "Upload C file",
        "assembly_generate_button": "Generate secure assembly code",
        "assembly_result_title": "Generated assembly output",
        "assembly_result_placeholder": "Generated output will appear here after execution.",
    },
    "de": {
        "title": "ScanCrypt — Post-Quanten-Sicherheit",
        "tagline": "Post-Quanten-Sicherheit",
        "nav_services": "Dienstleistungen",
        "nav_news": "Try Me",
        "nav_about": "Über",
        "nav_pricing": "Preise",
        "nav_contact": "Kontakt",
        "cta_start": "Kostenlos starten",
        "cta_demo": "Demo buchen",
        "landing_h1": "Post-Quanten-Kryptografie für eine sichere Zukunft scannen",
        "landing_lead": "Sichern Sie Ihre ML-DSA- und ML-KEM-Implementierungen. Erkennen Sie automatisch Seitenkanal-, Fehlerinjektions- und Implementierungs-Schwachstellen.",
        "supports_title": "Unterstützt:",
        "supports_list": ["Portables C", "ARM Cortex-M", "Embedded Firmware", "Linux", "Windows"],
        "index_title": "ScanCrypt Werkzeug",
        "tool_title": "ScanCrypt Werkzeug",
        "tool_description": "Wählen Sie einen Ordner mit lokalen Quelltextdateien aus und analysieren Sie jede unterstützte C/C++-Datei.",
        "upload_label": "Ordner hochladen",
        "upload_hint": "Verwenden Sie einen unterstützten Browser, um einen Ordner auszuwählen. Alle Dateien im Ordner werden verarbeitet.",
        "analyze_button": "Ordner analysieren",
        "analysis_complete": "Analyse abgeschlossen",
        "folder_label": "Ordner:",
        "files_analyzed": "Analysierte Dateien:",
        "unsupported_ignored": "Nicht unterstützte ignoriert:",
        "overall_algorithm": "Algorithmus",
        "overall_security_level": "Sicherheitsstufe",
        "overall_implementation_type": "Implementierungstyp",
        "assembly_title": "ScanCrypt — Sicherer Assembler-Generator",
        "assembly_h1": "Sichere Assembler-Generierung",
        "assembly_lead": "Dieser sichere Code-Generierungsablauf verarbeitet C/C++-Routinen über eine SSA-ähnliche Zwischenrepräsentation, leitet Sicherheitskontext für Parameter und Funktionsaufrufe ab, führt Taint-Tracking über Basic Blocks aus und erzeugt gehärtete Assembler-Ausgabe mit schutzorientierten Transformationen. Das aktuelle Generierungsprofil zielt auf eingebettete ARM-Cortex-M-Plattformen (ARMv6-M-ähnliche Ausgabe) und eignet sich damit für ressourcenbegrenzte Firmware-Umgebungen.",
        "assembly_input_title": "C-Quelltext Eingabe",
        "assembly_input_help": "Fügen Sie unten C-Code ein oder laden Sie eine C/C++-Datei hoch.",
        "assembly_upload_label": "C-Datei hochladen",
        "assembly_generate_button": "Sicheren Assembler-Code generieren",
        "assembly_result_title": "Generierte Assembler-Ausgabe",
        "assembly_result_placeholder": "Die generierte Ausgabe wird nach der Ausführung hier angezeigt.",
    },
}


def get_lang_from_request():
    lang = request.args.get("lang")
    if lang:
        session["lang"] = lang
    return session.get("lang", "en")


def detect_input_function_name(source: str) -> str | None:
    function_def = re.search(
        r"\b(?:static\s+|inline\s+|extern\s+|const\s+)*"
        r"(?:void|int|unsigned|signed|long|short|char|uint\d+_t|int\d+_t|size_t|bool|float|double)"
        r"(?:\s+|\s*\*+\s*)([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{",
        source,
        re.MULTILINE,
    )
    if function_def:
        return function_def.group(1)
    return None


def detect_supported_operations(source: str) -> list[str]:
    operation_patterns = {
        "Reduction": r"\b(reduce|poly_reduce|montgomery_reduce|barrett_reduce)\b",
        "Polynomial arithmetic": r"\b(poly|polynomial|ntt|invntt)\b",
        "Modular arithmetic": r"\b(mod|montgomery|barrett)\b",
        "Bitwise operations": r"\b(\^|\||&|<<|>>)\b",
    }

    matches = []
    for name, pattern in operation_patterns.items():
        if re.search(pattern, source, re.IGNORECASE):
            matches.append(name)
    return matches


def basic_assembly_syntax_check(assembly_text: str) -> tuple[bool, list[str]]:
    issues: list[str] = []
    asm_lines = [line for line in assembly_text.splitlines() if line.strip()]

    if not asm_lines:
        return False, ["No assembly output lines detected."]

    has_instruction_like = any(
        re.match(r"^\s*(\.[A-Za-z_]+|[A-Za-z_][A-Za-z0-9_]*:|[a-z]{2,}\b)", line)
        for line in asm_lines
    )
    if not has_instruction_like:
        issues.append("Output does not look like assembler syntax.")

    for idx, line in enumerate(asm_lines, start=1):
        stripped = line.strip()
        if stripped.endswith(":") and " " in stripped:
            issues.append(f"Line {idx}: malformed label syntax '{stripped}'.")

    return len(issues) == 0, issues


def compiler_assemble_check(assembly_text: str, target_key: str) -> tuple[bool | None, str]:
    target = SUPPORTED_TARGETS.get(target_key, SUPPORTED_TARGETS["cortex-m4"])
    gcc = shutil.which("arm-none-eabi-gcc")

    if not gcc:
        return None, "arm-none-eabi-gcc not found; compilation check skipped."

    try:
        with tempfile.TemporaryDirectory(prefix="scancrypt_asm_check_") as tmpdir:
            asm_file = Path(tmpdir) / "candidate.s"
            out_file = Path(tmpdir) / "candidate.o"
            asm_file.write_text(assembly_text, encoding="utf-8")

            cmd = [
                gcc,
                "-x",
                "assembler",
                "-c",
                str(asm_file),
                "-o",
                str(out_file),
                "-mthumb",
                f"-mcpu={target['mcpu']}",
            ]
            compile_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if compile_result.returncode == 0:
                return True, "Compilation succeeded."

            stderr = (compile_result.stderr or "").strip()
            return False, stderr or "Compilation failed."
    except subprocess.TimeoutExpired:
        return False, "Compilation check timed out."
    except Exception as exc:
        return False, f"Compilation check failed: {exc}"


@app.route("/upload-logo", methods=["POST"])
def upload_logo():
    file = request.files.get("company_logo")
    if not file or file.filename == "":
        flash("No file selected for upload.", "warning")
        return redirect(request.referrer or url_for("landing"))

    if not allowed_image(file.filename):
        flash("Unsupported file type. Use PNG/JPG/SVG/GIF/WEBP.", "danger")
        return redirect(request.referrer or url_for("landing"))

    suffix = Path(file.filename).suffix.lower()
    filename = f"company_logo{suffix}"
    save_path = UPLOAD_FOLDER / filename
    file.save(str(save_path))

    flash("Logo uploaded successfully.", "success")
    return redirect(request.referrer or url_for("landing"))

KNOWN_ALGORITHMS = {
    "AES": [r"AES", r"aes_", r"rijndael"],
    "RSA": [r"RSA", r"rsa_", r"RSA_public_encrypt", r"RSA_private_decrypt"],
    "SHA-256": [r"SHA256", r"sha256", r"SHA-256"],
    "SHA-1": [r"SHA1", r"sha1", r"SHA-1"],
    "SHA-3": [r"SHA3", r"sha3", r"Keccak"],
    "ChaCha20": [r"ChaCha20", r"chacha20", r"XChaCha"],
    "Poly1305": [r"Poly1305", r"poly1305"],
    "Blowfish": [r"Blowfish", r"blowfish"],
    "Twofish": [r"Twofish", r"twofish"],
    "Camellia": [r"Camellia", r"camellia"],
    "ECDSA": [r"ECDSA", r"ecdsa"],
    "Ed25519": [r"Ed25519", r"ed25519"],
    "Salsa20": [r"Salsa20", r"salsa20"],
    "MD5": [r"MD5", r"md5"],
}

DILITHIUM_SIGNATURES = [
    r"DILITHIUM_MODE",
    r"DILITHIUM2",
    r"DILITHIUM3",
    r"DILITHIUM5",
    r"ML_DSA_44",
    r"ML_DSA_65",
    r"ML_DSA_87",
    r"CRYPTO_ALGNAME",
    r"poly_challenge",
    r"polyvecl",
    r"polyveck",
    r"rej_uniform",
    r"decompose",
    r"make_hint",
    r"use_hint",
]

DILITHIUM_VARIANT_PATTERNS = [
    (r"DILITHIUM2|ML_DSA_44", "Dilithium2"),
    (r"DILITHIUM3|ML_DSA_65", "Dilithium3"),
    (r"DILITHIUM5|ML_DSA_87", "Dilithium5"),
]

DILITHIUM_VARIANT_PARAMS = {
    (4, 4): "ML-DSA-44 / Dilithium2",
    (6, 5): "ML-DSA-65 / Dilithium3",
    (8, 7): "ML-DSA-87 / Dilithium5",
}

KYBER_SIGNATURES = [
    r"KYBER_K",
    r"KYBER_Q",
    r"KYBER_N",
    r"KYBER_ETA1",
    r"KYBER_ETA2",
    r"DU",
    r"DV",
    r"CRYPTO_ALGNAME",
    r"indcpa_keypair",
    r"indcpa_enc",
    r"indcpa_dec",
    r"gen_matrix",
    r"poly_compress",
    r"polyvec_compress",
    r"polyvec_decompress",
    r"pack_pk",
    r"pack_sk",
    r"pack_ciphertext",
    r"unpack_ciphertext",
    r"cbd2",
    r"cbd3",
    r"ntt",
    r"invntt",
    r"montgomery_reduce",
    r"barrett_reduce",
    r"kyber512",
    r"kyber768",
    r"kyber1024",
    r"ML_KEM_512",
    r"ML_KEM_768",
    r"ML_KEM_1024",
]

KYBER_VARIANT_PATTERNS = [
    (r"ML_KEM_512|KYBER512|kyber512", "ML-KEM-512"),
    (r"ML_KEM_768|KYBER768|kyber768", "ML-KEM-768"),
    (r"ML_KEM_1024|KYBER1024|kyber1024", "ML-KEM-1024"),
]

KYBER_K_MAPPING = {
    2: "ML-KEM-512",
    3: "ML-KEM-768",
    4: "ML-KEM-1024",
}

KYBER_PARAMETER_COMBOS = {
    (3, 10, 4): "ML-KEM-512",
    (2, 8, 4): "ML-KEM-768",
    (2, 11, 5): "ML-KEM-1024",
}

SECURITY_LEVELS = {
    "AES": "128/192/256-bit symmetric security",
    "RSA": "Depends on key size (typically 2048+ bit asymmetric security)",
    "SHA-256": "256-bit collision resistance",
    "SHA-1": "80-bit collision resistance (broken for collision resistance)",
    "SHA-3": "256-bit collision resistance",
    "ChaCha20": "256-bit symmetric security",
    "Poly1305": "128-bit authentication security",
    "Blowfish": "Up to 448-bit key security",
    "Twofish": "128/192/256-bit symmetric security",
    "Camellia": "128/192/256-bit symmetric security",
    "ECDSA": "Depends on curve size (typically 256-bit security for P-256)",
    "Ed25519": "128-bit security",
    "Salsa20": "256-bit symmetric security",
    "MD5": "Broken (less than 64-bit collision security)",
}

IMPLEMENTATION_TYPES = [
    (r"__m128i|_mm_aesenc_si128|wmmintrin|invpcid|aesni|aes_.*intrin", "Hardware-accelerated AES / AES-NI implementation"),
    (r"inline.*__attribute__\(\(always_inline\)\)|__attribute__\(\(always_inline\)\)|static inline", "Optimized inline C implementation"),
    (r"uint8_t.*SBOX|S-BOX|S_BOX|s_box|lookup.*table|static const .*\[\].*\=\{", "Lookup-table based implementation"),
    (r"(>>|<<|\^|&|\|).*\bunsigned\b|bitwise|rotate|rotr|rotl", "Bitwise or bit-sliced implementation"),
    (r"#include <openssl|#include <crypto|#include <stdint.h>|#include <string.h>", "Portable C implementation"),
]


def parse_integer_parameter(code: str, name: str):
    patterns = [
        rf"#define\s+{name}\s+(\d+)",
        rf"\bconst\s+int\s+{name}\s*=\s*(\d+)",
        rf"\bint\s+{name}\s*=\s*(\d+)",
        rf"\b{name}\b\s*=\s*(\d+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, code)
        if match:
            return int(match.group(1))
    return None


def detect_kyber_variant(code: str) -> str | None:
    # First check for explicit Kyber variant names
    for pattern, name in KYBER_VARIANT_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            return name

    # Then check for K parameter mapping
    k_value = parse_integer_parameter(code, "KYBER_K")
    if k_value is not None and k_value in KYBER_K_MAPPING:
        return KYBER_K_MAPPING[k_value]

    # Check parameter combinations
    eta1 = parse_integer_parameter(code, "KYBER_ETA1")
    du = parse_integer_parameter(code, "DU")
    dv = parse_integer_parameter(code, "DV")
    if eta1 is not None and du is not None and dv is not None:
        return KYBER_PARAMETER_COMBOS.get((eta1, du, dv))

    # Only match generic Kyber signatures if we have at least 3 specific Kyber identifiers
    kyber_specific = [r"KYBER_K", r"KYBER_ETA", r"indcpa_", r"cbd2", r"cbd3", r"ML_KEM"]
    matches = sum(1 for pattern in kyber_specific if re.search(pattern, code, re.IGNORECASE))
    if matches >= 2 and any(re.search(pattern, code, re.IGNORECASE) for pattern in KYBER_SIGNATURES):
        return "ML-KEM"

    return None


def detect_dilithium_variant(code: str) -> str | None:
    for pattern, name in DILITHIUM_VARIANT_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            return name

    if any(re.search(pattern, code, re.IGNORECASE) for pattern in DILITHIUM_SIGNATURES):
        return "Dilithium"

    return None


def detect_algorithm(code: str) -> str:
    # Check for Dilithium-specific identifiers first (more distinctive)
    dilithium_variant = detect_dilithium_variant(code)
    if dilithium_variant:
        return dilithium_variant

    # Then check for Kyber/ML-KEM
    kyber_variant = detect_kyber_variant(code)
    if kyber_variant:
        return kyber_variant

    for name, patterns in KNOWN_ALGORITHMS.items():
        for pattern in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return name
    return "Unknown algorithm"


def dilithium_security_level(code: str) -> str:
    k_value = parse_integer_parameter(code, "K")
    l_value = parse_integer_parameter(code, "L")
    if k_value is not None and l_value is not None:
        return DILITHIUM_VARIANT_PARAMS.get((k_value, l_value), "Unknown Dilithium variant")
    return "Dilithium family detected, variant unknown"


def kyber_security_level(code: str, algorithm: str) -> str:
    variant = algorithm if algorithm in KYBER_K_MAPPING.values() else None
    if not variant:
        k_value = parse_integer_parameter(code, "KYBER_K")
        if k_value is not None:
            variant = KYBER_K_MAPPING.get(k_value)

    if not variant:
        eta1 = parse_integer_parameter(code, "KYBER_ETA1")
        du = parse_integer_parameter(code, "DU")
        dv = parse_integer_parameter(code, "DV")
        if eta1 is not None and du is not None and dv is not None:
            variant = KYBER_PARAMETER_COMBOS.get((eta1, du, dv))

    if not variant:
        if re.search(r"kyber512|ML_KEM_512", code, re.IGNORECASE):
            variant = "ML-KEM-512"
        elif re.search(r"kyber768|ML_KEM_768", code, re.IGNORECASE):
            variant = "ML-KEM-768"
        elif re.search(r"kyber1024|ML_KEM_1024", code, re.IGNORECASE):
            variant = "ML-KEM-1024"

    if variant == "ML-KEM-512":
        return "NIST Level 1 security"
    if variant == "ML-KEM-768":
        return "NIST Level 3 security"
    if variant == "ML-KEM-1024":
        return "NIST Level 5 security"
    if variant:
        return f"{variant} security"
    return "ML-KEM family detected, variant unknown"


def determine_security_level(algorithm: str, code: str) -> str:
    if algorithm.startswith("ML-KEM"):
        return kyber_security_level(code, algorithm)

    if algorithm.startswith("Dilithium"):
        return dilithium_security_level(code)

    if algorithm != "Unknown algorithm":
        return SECURITY_LEVELS.get(algorithm, "Security level not determined")

    if re.search(r"AES_128|AES128|AES192|AES256|rijndael", code, re.IGNORECASE):
        return "AES-level security (128/192/256-bit)"
    if re.search(r"RSA.*2048|2048.*RSA|4096.*RSA|RSA.*4096", code, re.IGNORECASE):
        return "Asymmetric security based on RSA key size"
    if re.search(r"SHA256|SHA-256", code, re.IGNORECASE):
        return "256-bit collision resistance"
    return "Security level could not be determined from implementation"


def determine_implementation_type(code: str, filename: str = "") -> str:
    if re.search(r"\b(masked|masking|share|NSHARES|refresh)\b", code, re.IGNORECASE):
        return "Masked Implementation"

    if re.search(r"__m256i|immintrin\.h|x86intrin\.h|avx2|__AVX2__", code, re.IGNORECASE):
        return "AVX2 Optimized"

    if re.search(r"stm32|cortex-m|cortex_m|CMSIS|__ARM_ARCH|ARM_M|__ARM_ARCH_", code, re.IGNORECASE):
        return "ARM Cortex-M/Embedded"

    if Path(filename).suffix.lower() in {".s", ".S", ".asm"} and re.search(r"cortex-m|stm32|arm", code, re.IGNORECASE):
        return "ARM Cortex-M/Embedded"

    if Path(filename).suffix.lower() in {".v", ".sv", ".vh", ".vhd", ".vhdl"}:
        return "Hardware/FPGA"

    if re.search(r"\b(module|assign|always|endmodule|entity|architecture|HLS)\b", code, re.IGNORECASE):
        return "Hardware/FPGA"

    if re.search(r"\bCMSIS\b|\bSTM32\b|\bCortex-M\b|__ARM_ARCH|ARM_M|__thumb__\b", code, re.IGNORECASE):
        return "ARM Cortex-M/Embedded"

    for pattern, description in IMPLEMENTATION_TYPES:
        if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
            return description
    return "Portable C/Reference"


def aggregate_category(values, mixed_label="Multiple detected"):
    counts = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1

    if not counts:
        return "Unknown"

    if len(counts) == 1:
        return next(iter(counts))

    if "Unknown algorithm" in counts and len(counts) > 1:
        counts.pop("Unknown algorithm")
        if len(counts) == 1:
            return next(iter(counts))

    if "ML-KEM" in counts and any(k.startswith("ML-KEM-") for k in counts if k != "ML-KEM"):
        counts.pop("ML-KEM")
        if len(counts) == 1:
            return next(iter(counts))

    if "Dilithium" in counts and any(k.startswith("Dilithium") for k in counts if k != "Dilithium"):
        counts.pop("Dilithium")
        if len(counts) == 1:
            return next(iter(counts))

    most_common = max(counts.items(), key=lambda item: (item[1], item[0]))[0]
    if counts[most_common] > 1:
        return most_common
    return f"{mixed_label}: {', '.join(sorted(counts.keys()))}"


def analyze_source_file(source_file):
    code = source_file.stream.read().decode("utf-8", errors="ignore")
    filename = source_file.filename
    algorithm = detect_algorithm(code)
    security_level = determine_security_level(algorithm, code)
    implementation_type = determine_implementation_type(code, filename)
    evidence = {
        "matched_identifiers": [],
        "matched_parameters": {},
        "matched_files": [filename],
    }

    if algorithm.startswith("ML-KEM"):
        evidence["matched_identifiers"] = [
            pat for pat in KYBER_SIGNATURES if re.search(pat, code, re.IGNORECASE)
        ]
        params = {
            "KYBER_K": parse_integer_parameter(code, "KYBER_K"),
            "KYBER_ETA1": parse_integer_parameter(code, "KYBER_ETA1"),
            "DU": parse_integer_parameter(code, "DU"),
            "DV": parse_integer_parameter(code, "DV"),
        }
        evidence["matched_parameters"] = {k: v for k, v in params.items() if v is not None}
    elif algorithm.startswith("Dilithium"):
        evidence["matched_identifiers"] = [
            pat for pat in DILITHIUM_SIGNATURES if re.search(pat, code, re.IGNORECASE)
        ]
    else:
        evidence["matched_identifiers"] = [
            pat for pat_list in KNOWN_ALGORITHMS.values() for pat in pat_list if re.search(pat, code, re.IGNORECASE)
        ]

    confidence = 0.6
    if algorithm.startswith("ML-KEM") or algorithm.startswith("Dilithium"):
        confidence = 0.9
    elif algorithm == "Unknown algorithm" and evidence["matched_identifiers"]:
        confidence = 0.7

    return {
        "filename": filename,
        "algorithm": algorithm,
        "security_level": security_level,
        "implementation_type": implementation_type,
        "confidence": confidence,
        "evidence": evidence,
    }


@app.route("/scan", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        source_files = request.files.getlist("source_files")
        valid_files = [f for f in source_files if f and f.filename]

        if not valid_files:
            flash("Please choose a folder to upload with source files.", "warning")
            return redirect(url_for("index"))

        # Save uploaded files into a temporary directory and analyze the project as a whole
        tmpdir = tempfile.mkdtemp(prefix="scancrypt_upload_")
        for source_file in valid_files:
            filename = Path(source_file.filename)
            # Only save supported files (by extension or known name)
            suffix = filename.suffix.lower()
            if suffix in {".c", ".h", ".cpp", ".cc", ".hpp", ".s", ".asm"} or filename.name.lower() in {"cmakelists.txt", "makefile"}:
                try:
                    target = Path(tmpdir) / filename.name
                    # ensure parent exists
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source_file.stream.seek(0)
                    data = source_file.stream.read()
                    target.write_bytes(data)
                except Exception:
                    continue

        # Run the detector on the temporary directory
        try:
            project_result = analyze_project(tmpdir)
        except Exception as e:
            # fallback: original per-file analysis if detector fails
            flash(f"Internal analysis error: {e}", "danger")
            return redirect(url_for("index"))

        folder_name = Path(valid_files[0].filename).parts[0] if "/" in valid_files[0].filename or "\\" in valid_files[0].filename else valid_files[0].filename
        analyzed_files = [f.filename for f in valid_files if f and f.filename]

        # Build PDF report payload and generate downloadable report
        report_url = None
        try:
            safe_project = secure_filename(folder_name) or "project"
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"scancrypt_report_{safe_project}_{timestamp}.pdf"
            report_path = REPORTS_FOLDER / report_filename

            report_payload = {
                "project_name": folder_name,
                "client_name": "Client X",
                "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "tool_version": "1.0",
                "algorithm": project_result.get("algorithm", "Unknown"),
                "security_level": project_result.get("security_level", "Unknown"),
                "implementation_type": project_result.get("implementation_type", "Unknown"),
                "overall_risk": "Information" if project_result.get("algorithm", "Unknown") == "Unknown" else "Medium",
                "language": project_result.get("programming_language", "C/C++"),
                "build_system": project_result.get("build_system", "Unknown"),
                "files": project_result.get("files", 0),
                "source_files": project_result.get("c_source_files", 0),
                "header_files": project_result.get("header_files", 0),
                "lines_of_code": project_result.get("lines_of_code", 0),
                "analysis_confidence": project_result.get("analysis_confidence", "0%"),
                "detection_confidence": project_result.get("analysis_confidence", "0%"),
                "rules_executed": project_result.get("rules_executed", 0),
                "rules_passed": project_result.get("rules_passed", 0),
                "rules_failed": project_result.get("rules_failed", 0),
                "analysis_duration": "N/A",
                "detection_evidence": (
                    (project_result.get("algorithm_evidence", []) or [])
                    + (project_result.get("implementation_evidence", []) or [])
                    + (project_result.get("missing_information", []) or [])
                ),
                "findings": project_result.get("findings", []),
                "analysed_files": analyzed_files,
                "scan_configuration": "Default ScanCrypt profile",
                "supported_algorithms": ["ML-DSA (Dilithium)", "ML-KEM (Kyber)"],
                "supported_implementation_types": [
                    "Portable C / Reference",
                    "AVX2 Optimized",
                    "ARM Cortex-M / Embedded",
                    "Masked Implementation",
                    "Hardware / FPGA",
                ],
            }

            generate_scan_report(report_payload, str(report_path))
            report_url = url_for("static", filename=f"reports/{report_filename}")
        except Exception as e:
            flash(f"Report generation failed: {e}", "warning")

        result = {
            "folder_name": folder_name,
            "overall_algorithm": project_result.get("algorithm", "Unknown"),
            "overall_security_level": project_result.get("security_level", "Unknown"),
            "overall_implementation_type": project_result.get("implementation_type", "Unknown"),
            "total_files": project_result.get("files", 0),
            "c_files": project_result.get("c_source_files", 0),
            "h_files": project_result.get("header_files", 0),
            "total_loc": project_result.get("lines_of_code", 0),
            "build_system": project_result.get("build_system", "Unknown"),
            "confidence": project_result.get("analysis_confidence", "0%"),
            "algorithm_evidence": project_result.get("algorithm_evidence", [])[:50],
            "implementation_evidence": project_result.get("implementation_evidence", [])[:50],
            "missing_information": project_result.get("missing_information", []),
            "findings": project_result.get("findings", []),
            "rules_executed": project_result.get("rules_executed", 0),
            "rules_passed": project_result.get("rules_passed", 0),
            "rules_failed": project_result.get("rules_failed", 0),
            "report_url": report_url,
        }

    # pass logo URL if uploaded
    logo_fn = get_logo_filename()
    logo_url = url_for("static", filename=f"uploads/{logo_fn}") if logo_fn else None
    lang = get_lang_from_request()
    t = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    other_lang = "de" if lang == "en" else "en"
    other_lang_label = "DE" if lang == "en" else "EN"
    other_lang_title = "Deutsch" if lang == "en" else "English"
    return render_template(
        "index.html",
        result=result,
        logo_url=logo_url,
        t=t,
        current_lang=lang,
        other_lang=other_lang,
        other_lang_label=other_lang_label,
        other_lang_title=other_lang_title,
    )


@app.route("/", methods=["GET"])
def landing():
    logo_fn = get_logo_filename()
    logo_url = url_for("static", filename=f"uploads/{logo_fn}") if logo_fn else None
    lang = get_lang_from_request()
    t = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    other_lang = "de" if lang == "en" else "en"
    other_lang_label = "DE" if lang == "en" else "EN"
    other_lang_title = "Deutsch" if lang == "en" else "English"
    return render_template(
        "landing.html",
        logo_url=logo_url,
        t=t,
        current_lang=lang,
        other_lang=other_lang,
        other_lang_label=other_lang_label,
        other_lang_title=other_lang_title,
    )


@app.route("/assembly", methods=["GET", "POST"])
def assembly_generator():
    assembly_output = None
    source_input = ""
    selected_arch = "cortex-m4"
    generation_result = None

    if request.method == "POST":
        selected_arch = request.form.get("target_arch", "cortex-m4")
        if selected_arch not in SUPPORTED_TARGETS:
            selected_arch = "cortex-m4"

        source_input = (request.form.get("c_code") or "").strip()
        uploaded_file = request.files.get("c_file")

        if uploaded_file and uploaded_file.filename:
            suffix = Path(uploaded_file.filename).suffix.lower()
            if suffix not in {".c", ".h", ".cpp", ".cc", ".hpp", ".txt"}:
                flash("Unsupported file type for assembly generation.", "warning")
                return redirect(url_for("assembly_generator"))

            uploaded_text = uploaded_file.stream.read().decode("utf-8", errors="ignore").strip()
            if uploaded_text:
                source_input = uploaded_text

        if not source_input:
            flash("Please paste C code or upload a C file.", "warning")
            return redirect(url_for("assembly_generator"))

        if len(source_input) > 200_000:
            flash("Input too large. Keep source under 200KB for reliable processing.", "warning")
            return redirect(url_for("assembly_generator"))

        detected_ops = detect_supported_operations(source_input)
        input_function = detect_input_function_name(source_input) or "not detected"
        assumptions: list[str] = []
        warnings: list[str] = []

        if not detected_ops:
            warnings.append("No clearly supported operation pattern was detected in the input source.")

        if input_function == "not detected":
            warnings.append("Input function could not be identified from the provided source.")

        pommes_path = Path(__file__).parent / "PoMMES-main" / "release" / "POMMES"
        if not pommes_path.exists():
            flash("Generation executable not found under the configured release directory.", "danger")
            return redirect(url_for("assembly_generator"))

        execution_stdout = ""
        execution_stderr = ""
        exit_code = None

        try:
            with tempfile.TemporaryDirectory(prefix="pommes_input_") as tmpdir:
                temp_input = Path(tmpdir) / "input.c"
                temp_input.write_text(source_input, encoding="utf-8")

                run_result = subprocess.run(
                    [str(pommes_path)],
                    cwd=str(pommes_path.parent),
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )

            execution_stdout = run_result.stdout or ""
            execution_stderr = run_result.stderr or ""
            exit_code = run_result.returncode

            combined = execution_stdout
            if execution_stderr:
                combined = f"{combined}\n{execution_stderr}" if combined else execution_stderr

            assembly_output = (combined or "").strip() or "No output produced by the generation engine."

            if run_result.returncode != 0:
                flash(f"Generation engine returned a non-zero exit code: {run_result.returncode}", "warning")
        except subprocess.TimeoutExpired:
            flash("Generation engine execution timed out.", "danger")
        except Exception as exc:
            flash(f"Generation engine execution failed: {exc}", "danger")

        syntax_ok, syntax_issues = basic_assembly_syntax_check(assembly_output or "")
        compile_ok, compile_message = compiler_assemble_check(assembly_output or "", selected_arch)

        mapping_notes = [
            f"Input function candidate: {input_function}",
            "Generated output is currently produced by the executable's configured internal case-study flow.",
        ]
        assumptions.append("Operation support is based on pattern detection, not full semantic verification.")
        assumptions.append("Target profile selection configures validation context and reporting assumptions.")

        limitations = [
            "Generated output is an implementation candidate and is not automatically secure.",
            "Functional equivalence between input C and generated assembly is not formally verified.",
            "Current executable workflow may rely on internal benchmark/case-study inputs.",
            "Supported C subset is intentionally limited to the documented input profile.",
        ]

        countermeasures = [
            "instruction replacement",
            "register allocation constraints",
            "hardened sequence generation",
        ]

        artifact_base = f"asm_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:8]}"
        source_filename = f"{artifact_base}.c"
        asm_filename = f"{artifact_base}.s"
        log_filename = f"{artifact_base}.log"

        source_path = ASSEMBLY_OUTPUT_FOLDER / source_filename
        asm_path = ASSEMBLY_OUTPUT_FOLDER / asm_filename
        log_path = ASSEMBLY_OUTPUT_FOLDER / log_filename

        source_path.write_text(source_input, encoding="utf-8")
        asm_path.write_text(assembly_output or "", encoding="utf-8")
        log_path.write_text(
            "\n".join(
                [
                    "ScanCrypt Assembly Generation Execution Log",
                    f"Timestamp: {datetime.now().isoformat()}",
                    f"Target: {SUPPORTED_TARGETS[selected_arch]['label']}",
                    f"Input function: {input_function}",
                    f"Detected operations: {', '.join(detected_ops) if detected_ops else 'None'}",
                    f"Generator exit code: {exit_code}",
                    "",
                    "[STDOUT]",
                    execution_stdout,
                    "",
                    "[STDERR]",
                    execution_stderr,
                    "",
                    "[SYNTAX CHECK]",
                    f"ok={syntax_ok}",
                    *syntax_issues,
                    "",
                    "[COMPILATION CHECK]",
                    f"result={compile_ok}",
                    compile_message,
                    "",
                    "[WARNINGS]",
                    *warnings,
                    "",
                    "[ASSUMPTIONS]",
                    *assumptions,
                    "",
                    "[LIMITATIONS]",
                    *limitations,
                ]
            ),
            encoding="utf-8",
        )

        generation_result = {
            "title": "Generated Implementation Candidate",
            "target": SUPPORTED_TARGETS[selected_arch]["label"],
            "input_function": input_function,
            "countermeasures": countermeasures,
            "syntax_ok": syntax_ok,
            "syntax_issues": syntax_issues,
            "compile_ok": compile_ok,
            "compile_message": compile_message,
            "equivalence_note": "Functional equivalence not yet formally verified.",
            "detected_operations": detected_ops,
            "warnings": warnings,
            "assumptions": assumptions,
            "limitations": limitations,
            "mapping_notes": mapping_notes,
            "flow_steps": FLOW_STEPS,
            "downloads": {
                "source": url_for("static", filename=f"reports/assembly/{source_filename}"),
                "assembly": url_for("static", filename=f"reports/assembly/{asm_filename}"),
                "log": url_for("static", filename=f"reports/assembly/{log_filename}"),
            },
        }

    logo_fn = get_logo_filename()
    logo_url = url_for("static", filename=f"uploads/{logo_fn}") if logo_fn else None
    lang = get_lang_from_request()
    t = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    other_lang = "de" if lang == "en" else "en"
    other_lang_label = "DE" if lang == "en" else "EN"
    other_lang_title = "Deutsch" if lang == "en" else "English"
    return render_template(
        "assembly.html",
        logo_url=logo_url,
        t=t,
        current_lang=lang,
        other_lang=other_lang,
        other_lang_label=other_lang_label,
        other_lang_title=other_lang_title,
        assembly_output=assembly_output,
        source_input=source_input,
        selected_arch=selected_arch,
        supported_targets=SUPPORTED_TARGETS,
        supported_c_subset=SUPPORTED_C_SUBSET,
        generation_result=generation_result,
    )


@app.route("/pricing", methods=["GET"])
def pricing():
    logo_fn = get_logo_filename()
    logo_url = url_for("static", filename=f"uploads/{logo_fn}") if logo_fn else None
    lang = get_lang_from_request()
    t = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    other_lang = "de" if lang == "en" else "en"
    other_lang_label = "DE" if lang == "en" else "EN"
    other_lang_title = "Deutsch" if lang == "en" else "English"
    return render_template(
        "pricing.html",
        logo_url=logo_url,
        t=t,
        current_lang=lang,
        other_lang=other_lang,
        other_lang_label=other_lang_label,
        other_lang_title=other_lang_title,
    )


@app.route("/about", methods=["GET"])
def about():
    logo_fn = get_logo_filename()
    logo_url = url_for("static", filename=f"uploads/{logo_fn}") if logo_fn else None
    lang = get_lang_from_request()
    t = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    other_lang = "de" if lang == "en" else "en"
    other_lang_label = "DE" if lang == "en" else "EN"
    other_lang_title = "Deutsch" if lang == "en" else "English"
    return render_template(
        "about.html",
        logo_url=logo_url,
        t=t,
        current_lang=lang,
        other_lang=other_lang,
        other_lang_label=other_lang_label,
        other_lang_title=other_lang_title,
    )


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()
        
        if not all([name, email, subject, message]):
            flash("Please fill in all fields.", "warning")
            return redirect(url_for("contact"))
        
        flash("Thank you for your message! We'll get back to you soon.", "success")
        return redirect(url_for("contact"))
    
    logo_fn = get_logo_filename()
    logo_url = url_for("static", filename=f"uploads/{logo_fn}") if logo_fn else None
    lang = get_lang_from_request()
    t = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    other_lang = "de" if lang == "en" else "en"
    other_lang_label = "DE" if lang == "en" else "EN"
    other_lang_title = "Deutsch" if lang == "en" else "English"
    return render_template(
        "contact.html",
        logo_url=logo_url,
        t=t,
        current_lang=lang,
        other_lang=other_lang,
        other_lang_label=other_lang_label,
        other_lang_title=other_lang_title,
    )


@app.route("/services", methods=["GET"])
def services():
    logo_fn = get_logo_filename()
    logo_url = url_for("static", filename=f"uploads/{logo_fn}") if logo_fn else None
    lang = get_lang_from_request()
    t = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    other_lang = "de" if lang == "en" else "en"
    other_lang_label = "DE" if lang == "en" else "EN"
    other_lang_title = "Deutsch" if lang == "en" else "English"
    return render_template(
        "services.html",
        logo_url=logo_url,
        t=t,
        current_lang=lang,
        other_lang=other_lang,
        other_lang_label=other_lang_label,
        other_lang_title=other_lang_title,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
