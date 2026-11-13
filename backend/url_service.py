import socket
import re
from urllib.parse import urlparse
from typing import Dict, Any
from backend.security import validate_url_safe

# Suspicious TLDs commonly abused in automated phishing / smishing
HIGH_RISK_TLDS = {
    "xyz", "top", "buzz", "rest", "cfd", "click", "work", "loan", "zip", "mov",
    "cam", "link", "guru", "surf", "casa", "icu", "site", "online", "live"
}

# Targeted financial and technology brand patterns
TARGETED_BRANDS = [
    "paypal", "chase", "wells", "fargo", "citibank", "bankofamerica", "netflix",
    "amazon", "apple", "microsoft", "google", "binance", "coinbase", "metamask",
    "fedex", "usps", "dhl", "ups", "irs", "gov", "whatsapp", "telegram", "facebook"
]

def inspect_url_heuristics(raw_url: str) -> Dict[str, Any]:
    """
    Performs fast heuristic and DNS analysis on a submitted URL.
    Returns structured domain reputation indicators.
    """
    is_safe, message_or_url = validate_url_safe(raw_url)
    if not is_safe:
        return {
            "is_valid": False,
            "error": message_or_url,
            "suspicion_score": 100,
            "flags": ["SSRF_BLOCKED_OR_INVALID_DESTINATION"]
        }

    normalized_url = message_or_url
    parsed = urlparse(normalized_url)
    hostname = parsed.hostname.lower()

    flags = []
    suspicion_score = 0

    # 1. Check TLD
    parts = hostname.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    if tld in HIGH_RISK_TLDS:
        flags.append(f"HIGH_RISK_DISPOSABLE_TLD (.{tld})")
        suspicion_score += 25

    # 2. Check for brand typosquatting / hyphenated spoofing
    for brand in TARGETED_BRANDS:
        if brand in hostname:
            # If the domain is not the official brand domain
            official_domain = f"{brand}.com"
            if hostname != official_domain and not hostname.endswith(f".{official_domain}"):
                flags.append(f"BRAND_IMPERSONATION_HOMOGLYPH_HOOK ({brand})")
                suspicion_score += 45
                break

    # 3. Excessive subdomains or hyphens
    if hostname.count("-") >= 2:
        flags.append("EXCESSIVE_HYPHENATION_MASK")
        suspicion_score += 15
    if len(parts) > 3:
        flags.append("DEEP_SUBDOMAIN_DECEPTION")
        suspicion_score += 15

    # 4. Numerical IP address or lookalike
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
        flags.append("RAW_IP_DESTINATION_HOST")
        suspicion_score += 35

    # 5. DNS Resolution
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except Exception:
        flags.append("DNS_UNRESOLVABLE_DOMAIN")
        suspicion_score += 20

    return {
        "is_valid": True,
        "url": normalized_url,
        "hostname": hostname,
        "tld": tld,
        "resolved_ip": resolved_ip,
        "flags": flags,
        "suspicion_score": min(suspicion_score, 100),
        "has_suspicious_markers": suspicion_score >= 30
    }
