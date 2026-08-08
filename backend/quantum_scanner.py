"""
Quantum Vulnerability Scanner — Backend
PQC Track | NIST 2024 Post-Quantum Readiness Audit
"""

import ssl
import socket
import json
from datetime import datetime, timezone


# ── NIST PQC Threat Matrix ─────────────────────────────────────────────────
# Source: NIST IR 8413, FIPS 203/204/205 (2024)

VULNERABLE_ALGORITHMS = {
    # Key Exchange / KEM
    "rsaEncryption":        {"risk": "CRITICAL", "reason": "Shor's algorithm breaks RSA in polynomial time on a CRQC."},
    "rsa":                  {"risk": "CRITICAL", "reason": "Shor's algorithm breaks RSA in polynomial time on a CRQC."},
    "id-ecPublicKey":       {"risk": "CRITICAL", "reason": "Shor's algorithm solves ECDLP, breaking all ECC-based schemes."},
    "ec":                   {"risk": "CRITICAL", "reason": "Shor's algorithm solves ECDLP, breaking all ECC-based schemes."},
    "id-dh":                {"risk": "CRITICAL", "reason": "Shor's algorithm breaks Diffie-Hellman key exchange."},
    "dhKeyAgreement":       {"risk": "CRITICAL", "reason": "Shor's algorithm breaks Diffie-Hellman key exchange."},
    # Signatures
    "sha256WithRSAEncryption":  {"risk": "CRITICAL", "reason": "RSA signature — broken by Shor's algorithm."},
    "sha384WithRSAEncryption":  {"risk": "CRITICAL", "reason": "RSA signature — broken by Shor's algorithm."},
    "sha512WithRSAEncryption":  {"risk": "CRITICAL", "reason": "RSA signature — broken by Shor's algorithm."},
    "ecdsa-with-SHA256":        {"risk": "CRITICAL", "reason": "ECDSA signature — broken by Shor's algorithm."},
    "ecdsa-with-SHA384":        {"risk": "CRITICAL", "reason": "ECDSA signature — broken by Shor's algorithm."},
    "ecdsa-with-SHA512":        {"risk": "CRITICAL", "reason": "ECDSA signature — broken by Shor's algorithm."},
    "dsa":                      {"risk": "HIGH",     "reason": "DSA relies on discrete logarithm — vulnerable to Shor's."},
    # Symmetric (weakened, not broken)
    "aes128":               {"risk": "MEDIUM", "reason": "Grover's algorithm halves effective key length to 64-bit. Upgrade to AES-256."},
    "des":                  {"risk": "CRITICAL", "reason": "Already classically broken. Completely obsolete."},
    "3des":                 {"risk": "HIGH",    "reason": "Deprecated. Grover reduces security further."},
    "tls_aes_128_gcm_sha256": {"risk": "MEDIUM", "reason": "AES-128: Grover's algorithm halves effective key length to 64-bit. Upgrade to AES-256."},
    "tls_aes_256_gcm_sha384": {"risk": "SAFE",   "reason": "AES-256 remains quantum-safe. Grover's reduces to 128-bit effective — still acceptable."},
}

SAFE_ALGORITHMS = {
    "id-ml-kem":    "FIPS 203 — ML-KEM (Kyber). NIST-standardised PQC KEM. ✓",
    "id-ml-dsa":    "FIPS 204 — ML-DSA (Dilithium). NIST-standardised PQC signature. ✓",
    "id-slh-dsa":   "FIPS 205 — SLH-DSA (SPHINCS+). NIST-standardised PQC signature. ✓",
    "id-falcon":    "Falcon — NIST Round 4 alternate. Lattice-based signature. ✓",
}

NIST_REMEDIATION = {
    "CRITICAL": {
        "action": "Immediate migration required",
        "kem_upgrade":  "Replace RSA/ECDH key exchange → FIPS 203 ML-KEM-768 or ML-KEM-1024",
        "sig_upgrade":  "Replace RSA/ECDSA signatures → FIPS 204 ML-DSA-65 or SLH-DSA (FIPS 205)",
        "interim":      "Enable hybrid TLS (X25519Kyber768) as a transitional measure now — supported in Chrome 116+ and Cloudflare.",
        "harvest_risk": "HIGH — data encrypted today can be harvested and decrypted post-CRQC.",
    },
    "HIGH": {
        "action": "Plan migration within 12 months",
        "sig_upgrade":  "Transition signatures to FIPS 204 ML-DSA.",
        "interim":      "Prioritise crypto-agility: decouple algorithm from implementation so migration is a config change.",
        "harvest_risk": "MEDIUM-HIGH",
    },
    "MEDIUM": {
        "action": "Upgrade symmetric key length",
        "sym_upgrade":  "Move from AES-128 → AES-256. Grover's halves security; 256-bit remains safe.",
        "harvest_risk": "LOW",
    },
}


# ── Certificate Extraction ─────────────────────────────────────────────────

def fetch_certificate(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    """
    Opens a TLS connection to hostname:port and returns the parsed certificate dict.
    Uses ssl.get_server_certificate + DER decode for full field access.
    """
    hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0]

    ctx = ssl.create_default_context()
    # Don't verify cert — we want to scan even broken/expired certs
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_der  = ssock.getpeercert(binary_form=True)
            cert_dict = ssock.getpeercert()          # human-readable dict
            cipher    = ssock.cipher()               # (name, protocol, bits)
            tls_ver   = ssock.version()

    return {
        "hostname":         hostname,
        "cert_dict":        cert_dict,
        "cert_der":         cert_der,
        "cipher_suite":     cipher[0] if cipher else "unknown",
        "tls_version":      tls_ver,
        "cipher_bits":      cipher[2] if cipher else 0,
    }


def parse_cert_algorithms(raw: dict) -> dict:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    cert = x509.load_der_x509_certificate(raw["cert_der"], default_backend())

    pub_key_algo = cert.public_key().__class__.__name__
    # Normalise to our threat matrix keys
    if "EC" in pub_key_algo or "Elliptic" in pub_key_algo:
        pub_key_algo = "id-ecPublicKey"
    elif "RSA" in pub_key_algo:
        pub_key_algo = "rsaEncryption"

    sig_algo = cert.signature_algorithm_oid.dotted_string
    sig_algo_name = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    # Map to our threat matrix keys
    full_sig = f"{pub_key_algo}+{sig_algo_name}"
    if "EC" in pub_key_algo:
        sig_algo_display = f"ecdsa-with-SHA{sig_algo_name.replace('sha', '').upper()}"
    elif "RSA" in pub_key_algo:
        sig_algo_display = f"sha{sig_algo_name.replace('sha', '').upper()}WithRSAEncryption"
    else:
        sig_algo_display = sig_algo_name

    try:
        issuer_cn = cert.issuer.get_attributes_for_oid(
            x509.oid.NameOID.ORGANIZATION_NAME
        )[0].value
    except (IndexError, Exception):
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )[0].value
        except Exception:
            issuer_cn = "Unknown CA"

    not_after = cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT")

    return {
        "hostname":      raw["hostname"],
        "subject_cn":    cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value,
        "issuer_cn":     issuer_cn,
        "not_before":    cert.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT"),
        "not_after":     not_after,
        "pub_key_algo":  pub_key_algo,
        "sig_algo":      sig_algo_display,
        "cipher_suite":  raw["cipher_suite"],
        "tls_version":   raw["tls_version"],
        "cipher_bits":   raw["cipher_bits"],
    }

# ── Vulnerability Evaluation ───────────────────────────────────────────────

def evaluate_quantum_risk(parsed: dict) -> dict:
    """
    Cross-reference extracted algorithms against the threat matrix.
    Returns a structured risk report.
    """
    findings   = []
    risk_level = "SAFE"
    risk_score = 0          # 0–100

    checks = [
        ("Public Key Algorithm", parsed["pub_key_algo"]),
        ("Signature Algorithm",  parsed["sig_algo"]),
        ("Cipher Suite",         parsed["cipher_suite"]),
    ]

    for field, algo in checks:
        algo_key = algo.lower()

        # Match against vulnerable dict (substring match for flexibility)
        matched = None
        for vuln_key, vuln_data in VULNERABLE_ALGORITHMS.items():
            if vuln_key.lower() in algo_key or algo_key in vuln_key.lower():
                matched = (vuln_key, vuln_data)
                break

        if matched:
            findings.append({
                "field":   field,
                "algo":    algo,
                "risk":    matched[1]["risk"],
                "reason":  matched[1]["reason"],
            })
            # Score escalation
            r = matched[1]["risk"]
            if r == "CRITICAL" and risk_score < 90:
                risk_score = 90
            elif r == "HIGH" and risk_score < 65:
                risk_score = 65
            elif r == "MEDIUM" and risk_score < 40:
                risk_score = 40

            if r == "CRITICAL":
                risk_level = "CRITICAL"
            elif r == "HIGH" and risk_level != "CRITICAL":
                risk_level = "HIGH"
            elif r == "MEDIUM" and risk_level not in ("CRITICAL", "HIGH"):
                risk_level = "MEDIUM"

        else:
            # Check if it's a known-safe PQC algo
            is_safe = any(s.lower() in algo_key for s in SAFE_ALGORITHMS)
            findings.append({
                "field":  field,
                "algo":   algo,
                "risk":   "SAFE" if is_safe else "UNKNOWN",
                "reason": SAFE_ALGORITHMS.get(algo, "Algorithm not in threat matrix — manual review advised."),
            })

    remediation = NIST_REMEDIATION.get(risk_level, {})

    return {
        "hostname":      parsed["hostname"],
        "subject_cn":    parsed["subject_cn"],
        "issuer_cn":     parsed["issuer_cn"],
        "tls_version":   parsed["tls_version"],
        "not_after":     parsed["not_after"],
        "risk_level":    risk_level,
        "risk_score":    risk_score,
        "findings":      findings,
        "remediation":   remediation,
        "scanned_at":    datetime.now(timezone.utc).isoformat(),
    }


# ── Main Entry Point ───────────────────────────────────────────────────────

def scan(url: str) -> dict:
    """
    Full pipeline: fetch → parse → evaluate.
    Returns the complete report dict (JSON-serialisable).
    Raises exceptions on connection failure — caller should handle.
    """
    raw    = fetch_certificate(url)
    parsed = parse_cert_algorithms(raw)
    report = evaluate_quantum_risk(parsed)
    return report


# ── CLI quick-test ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "vitap.ac.in"
    print(f"\n🔍 Scanning {target} ...\n")
    try:
        result = scan(target)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"❌ Scan failed: {e}")
