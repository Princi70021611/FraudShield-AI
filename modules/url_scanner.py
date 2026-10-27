
import re
from urllib.parse import urlparse

def scan_url(url):
    url = url.strip()
    text = url.lower()
    score = 0
    reasons = []

    if not url:
        return {
            "risk": "Low",
            "score": 0,
            "reasons": ["Please enter a URL to scan"]
        }

    # Add a scheme so URLs such as example.com can be parsed
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()

    # 1. IP address used instead of a domain name
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        score += 3
        reasons.append("URL uses an IP address instead of a domain name")

    # 2. Suspicious URL characters
    if "@" in url:
        score += 3
        reasons.append("URL contains @, which can obscure the destination")

    # 3. HTTPS is absent
    if not url.lower().startswith("https://"):
        score += 1
        reasons.append("URL does not explicitly use HTTPS")

    # 4. Commonly suspicious words in the URL
    suspicious_words = [
        "login", "verify", "secure", "account",
        "update", "password", "otp", "wallet",
        "banking", "payment", "claim", "prize"
    ]

    found_words = [word for word in suspicious_words if word in text]
    if len(found_words) >= 3:
        score += 3
        reasons.append("Several sensitive or urgency-related words appear in the URL")
    elif len(found_words) >= 1:
        score += 1
        reasons.append("URL contains a sensitive or account-related word")

    # 5. URL shorteners
    shorteners = [
        "bit.ly", "tinyurl.com", "t.co",
        "is.gd", "cutt.ly", "shorturl.at"
    ]

    if any(host == domain or host.endswith("." + domain)
           for domain in shorteners):
        score += 2
        reasons.append("URL uses a link-shortening service")

    # 6. Unusually long URL
    if len(url) > 100:
        score += 2
        reasons.append("URL is unusually long")

    # 7. Multiple subdomains
    if len(host.split(".")) >= 5:
        score += 2
        reasons.append("URL has an unusually deep subdomain structure")

    # 8. Suspicious file extensions in path
    if re.search(r"\.(exe|apk|scr|bat|cmd)(?:$|[?#])", path):
        score += 3
        reasons.append("URL path points to a potentially risky executable file")

    # 9. Avoid treating a normal HTTPS URL as automatically safe
    if score >= 5:
        risk = "High"
    elif score >= 2:
        risk = "Medium"
    else:
        risk = "Low"

    if not reasons:
        reasons.append("No obvious URL warning signs detected")

    return {
        "risk": risk,
        "score": score,
        "reasons": reasons
    }
