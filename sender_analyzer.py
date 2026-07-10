import re


# Brands and their expected legitimate domains
BRAND_DOMAINS = {
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.in"],
    "google": ["google.com", "gmail.com"],
    "paypal": ["paypal.com"],
    "netflix": ["netflix.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "youtube": ["youtube.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "dropbox": ["dropbox.com"],
    "spotify": ["spotify.com"],
}

# Suspicious keywords often used in phishing sender domains
SUSPICIOUS_DOMAIN_KEYWORDS = [
    "support", "security", "update", "alert",
    "verify", "service",
]

# Free email providers
FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "mail.com", "yandex.com",
]


def _extract_email_parts(sender: str) -> tuple:
    """
    Extracts the display name and email address from a sender string.
    
    Handles formats like:
        "Amazon Support <orders@amaz0n-support.com>"
        "orders@amaz0n-support.com"
        "Amazon Support orders@amaz0n-support.com"
    
    Returns:
        (display_name: str, email: str, domain: str)
        Any part may be empty string if not found.
    """
    # Try to extract email from angle brackets first: "Name <email>"
    angle_match = re.search(r'<([^>]+@[^>]+)>', sender)
    if angle_match:
        email = angle_match.group(1).strip().lower()
        display_name = sender[:angle_match.start()].strip().strip('"').strip("'").strip()
    else:
        # Try to find a bare email in the string
        email_match = re.search(r'[\w.+-]+@[\w.-]+\.\w+', sender)
        if email_match:
            email = email_match.group(0).strip().lower()
            display_name = sender[:email_match.start()].strip().strip('"').strip("'").strip()
        else:
            return ("", "", "")
    
    domain = email.split("@")[-1] if "@" in email else ""
    return (display_name, email, domain)


def check_sender(sender: str) -> dict:
    """
    Analyzes a sender string for signs of phishing or impersonation.
    
    Accepts a sender string such as:
        "Amazon Support <orders@amaz0n-support.com>"
        "Amazon Support orders@amaz0n-support.com"
    
    Performs three checks:
    
    Check 1 — Display name spoofing (+30):
        Does the display name claim to be a known brand but the email domain
        doesn't match any of that brand's legitimate domains?
    
    Check 2 — Suspicious sender domain (+20):
        Does the email domain contain suspicious keywords (support, security,
        update, alert, verify, service) combined with a brand name?
    
    Check 3 — Free email provider impersonation (+15):
        Is the email from a free provider (gmail.com, yahoo.com, hotmail.com)
        while the display name claims to be a business?
    
    Returns a dictionary:
    {
        "flags": list[str],
        "score": int,
        "explanation": list[str],
        "display_name": str,
        "email": str,
        "domain": str
    }
    """
    result = {
        "flags": [],
        "score": 0,
        "explanation": [],
        "display_name": "",
        "email": "",
        "domain": "",
    }
    
    if not isinstance(sender, str) or not sender.strip():
        result["explanation"].append("Invalid or empty sender string.")
        return result
    
    display_name, email, domain = _extract_email_parts(sender)
    result["display_name"] = display_name
    result["email"] = email
    result["domain"] = domain
    
    if not email or not domain:
        result["explanation"].append("Could not extract email or domain from sender.")
        return result
    
    display_lower = display_name.lower()
    domain_lower = domain.lower()
    
    # ------------------------------------------------------------------
    # Check 1: Display name spoofing
    # ------------------------------------------------------------------
    for brand, legit_domains in BRAND_DOMAINS.items():
        if brand in display_lower:
            if domain_lower not in legit_domains:
                result["flags"].append("Display name spoofing")
                result["score"] += 30
                result["explanation"].append(
                    f"Display name spoofing: Display name contains '{brand}' "
                    f"but email domain '{domain}' does not match expected "
                    f"domains {legit_domains}."
                )
            # Only check the first matching brand
            break
    
    # ------------------------------------------------------------------
    # Check 2: Suspicious sender domain keywords + brand name
    # ------------------------------------------------------------------
    has_suspicious_keyword = any(kw in domain_lower for kw in SUSPICIOUS_DOMAIN_KEYWORDS)
    if has_suspicious_keyword:
        for brand in BRAND_DOMAINS:
            # Check if brand name (or a close variant) appears in the domain
            # e.g. "amaz0n-support.com" — normalize leet speak in domain
            normalized_domain = domain_lower.replace("0", "o").replace("1", "i").replace("3", "e").replace("$", "s").replace("4", "a")
            if brand.replace(" ", "") in normalized_domain:
                result["flags"].append("Suspicious sender domain")
                result["score"] += 20
                result["explanation"].append(
                    f"Suspicious sender domain: Domain '{domain}' contains "
                    f"suspicious keyword(s) combined with brand name '{brand}'."
                )
                break
    
    # ------------------------------------------------------------------
    # Check 3: Free email provider impersonation
    # ------------------------------------------------------------------
    if domain_lower in FREE_EMAIL_PROVIDERS and display_name:
        # Check if display name claims to be a brand
        for brand in BRAND_DOMAINS:
            if brand in display_lower:
                result["flags"].append("Free email provider impersonation")
                result["score"] += 15
                result["explanation"].append(
                    f"Free email provider impersonation: Display name claims "
                    f"to be '{brand}' but uses free email provider '{domain}'."
                )
                break
    
    return result
