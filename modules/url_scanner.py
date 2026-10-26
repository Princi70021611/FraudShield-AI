
from urllib.parse import urlparse
import ipaddress
import re

def scan_url(url):
    url = url.strip()
    reasons = []

    if not url:
        return {
            "risk": "Unknown",
            "score": 0,
            "reasons": ["Please enter a URL."]
        }

    candidate = url if "://" in url else "https://" + url

    try:
        parsed = urlparse(candidate)
        host = parsed.hostname

        if parsed.scheme not in ("http", "https") or not host:
            raise ValueError("Invalid URL")

    except ValueError:
        return {
            "risk": "Unknown",
            "score": 0,
            "reasons": ["URL format is invalid."]
        }

    score = 0
    host = host.lower()

    if parsed.scheme == "http":
        score += 1
        reasons.append("Connection does not use HTTPS.")

    if "@" in parsed.netloc:
        score += 2
        reasons.append("URL contains an @ symbol in its address section.")

    try:
        ipaddress.ip_address(host)
        score += 2
        reasons.append("URL uses a direct IP address instead of a domain.")
    except ValueError:
        pass

    if "xn--" in host:
        score += 2
        reasons.append("Domain contains an encoded internationalized name.")

    if len(url) > 120:
        score += 1
        reasons.append("URL is unusually long.")

    if len(host.split(".")) >= 5:
        score += 1
        reasons.append("Domain has many subdomain levels.")

    if re.search(r"(login|verify|claim|prize|urgent)", url.lower()):
        score += 1
        reasons.append("URL contains words sometimes used in deceptive links.")

    if score >= 4:
        risk = "High"
    elif score >= 2:
        risk = "Medium"
    else:
        risk = "Low"

    if not reasons:
        reasons.append("No obvious URL warning signs detected.")

    return {
        "risk": risk,
        "score": score,
        "reasons": reasons
    }
