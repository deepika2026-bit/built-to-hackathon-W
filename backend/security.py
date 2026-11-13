import re
import socket
import ipaddress
import hashlib
from urllib.parse import urlparse
from backend.config import IP_HASH_SALT

# Sensitive information regexes
CREDIT_CARD_REGEX = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
OTP_PIN_REGEX = re.compile(r"(?i)\b(?:otp|passcode|pin|cvv|secret|token)\s*[:=]\s*([0-9a-zA-Z]{4,8})\b")
EMAIL_ADDRESS_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")

# Private and reserved IP blocks for Anti-SSRF
FORBIDDEN_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def hash_client_ip(ip: str) -> str:
    """Hashes the client IP with a secret salt to prevent raw IP logging."""
    salted = f"{ip}:{IP_HASH_SALT}".encode("utf-8")
    return hashlib.sha256(salted).hexdigest()

def sanitize_pii(text: str) -> str:
    """Masks credit card numbers, OTPs, and private credentials in user text."""
    if not text:
        return ""
    
    # Redact potential credit card numbers (13 to 16 digits)
    def mask_card(match):
        raw = match.group(0)
        digits = re.sub(r"\D", "", raw)
        if 13 <= len(digits) <= 19:
            return f"[REDACTED_CARD_****{digits[-4:]}]"
        return raw

    sanitized = CREDIT_CARD_REGEX.sub(mask_card, text)
    
    # Redact OTP / PIN values
    sanitized = OTP_PIN_REGEX.sub(r"[REDACTED_OTP_CODE]", sanitized)
    
    return sanitized

def validate_url_safe(target_url: str) -> tuple[bool, str]:
    """
    Validates a URL against Server-Side Request Forgery (SSRF) vulnerabilities.
    Returns (is_safe: bool, reason_or_normalized_url: str).
    """
    if not target_url or not isinstance(target_url, str):
        return False, "Empty or invalid URL supplied."

    target_url = target_url.strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    try:
        parsed = urlparse(target_url)
    except Exception as e:
        return False, f"Malformed URL structure: {str(e)}"

    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported URL scheme: {parsed.scheme}. Only HTTP/HTTPS permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL lacks a valid hostname."

    hostname_lower = hostname.lower()

    # Block localhost / internal labels
    if hostname_lower in ("localhost", "local", "internal") or \
       hostname_lower.endswith((".localhost", ".local", ".internal")):
        return False, f"Forbidden local destination hostname '{hostname_lower}'."

    # Check if host is direct IP address
    try:
        ip = ipaddress.ip_address(hostname_lower)
        for net in FORBIDDEN_IP_NETWORKS:
            if ip in net:
                return False, f"Direct access to private or reserved IP range ({ip}) is blocked."
    except ValueError:
        # Not a raw IP literal; resolve DNS
        try:
            resolved_ips = socket.getaddrinfo(hostname_lower, None)
            for addr_info in resolved_ips:
                ip_str = addr_info[4][0]
                ip_obj = ipaddress.ip_address(ip_str)
                for net in FORBIDDEN_IP_NETWORKS:
                    if ip_obj in net:
                        return False, f"Domain {hostname_lower} resolves to forbidden private network ({ip_str})."
        except socket.gaierror:
            # Domain could not be resolved; could be unregistered or typosquatting
            pass
        except Exception:
            pass

    return True, target_url
