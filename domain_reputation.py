import re
import datetime
from urllib.parse import urlparse
import whois

def check_domain_reputation(text: str) -> dict:
    """
    Extracts domains from URLs in the input text and performs a WHOIS lookup 
    to retrieve the domain creation date, determining the domain age and reputation.
    
    Checks per unique domain:
    1. Domain Age < 30 days (+20 score, flags)
    2. Domain Age between 30 and 180 days (+10 score, flags)
    3. WHOIS lookup fails or creation date is unavailable (+10 score, flags)
    4. Top Level Domain (TLD) is in suspicious list (.xyz, .top, .click, .ru, .tk, .ml, .ga, .cf) (+10 score)
    
    Returns a dictionary:
    {
        "domains_checked": list[dict],
        "score": int,
        "explanation": list[str]
    }
    """
    if not isinstance(text, str):
        return {
            "domains_checked": [],
            "score": 0,
            "explanation": ["Invalid input: text must be a string."]
        }
        
    suspicious_tlds = {".xyz", ".top", ".click", ".ru", ".tk", ".ml", ".ga", ".cf"}
    
    # Extract URLs starting with http:// or https://
    url_pattern = r'https?://[^\s<>"]+'
    urls_found = re.findall(url_pattern, text)
    
    # Extract unique domains
    unique_domains = []
    for url in urls_found:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0].lower()
            if domain and domain not in unique_domains:
                unique_domains.append(domain)
        except Exception:
            continue
            
    domains_checked = []
    score = 0
    explanation = []
    
    now = datetime.datetime.now()
    
    for domain in unique_domains:
        # Check suspicious TLD
        domain_parts = domain.split('.')
        if len(domain_parts) > 1:
            tld = "." + domain_parts[-1]
            if tld in suspicious_tlds:
                score += 10
                explanation.append(f"Suspicious TLD ({tld}) detected: {domain}")
        
        # Try WHOIS lookup
        creation_date = None
        age_days = None
        lookup_success = False
        
        try:
            # whois.whois can raise exceptions or timeout
            w = whois.whois(domain)
            raw_creation_date = w.get('creation_date')
            
            # Resolve creation date which can be a datetime, list of datetimes, or string
            resolved_date = None
            if isinstance(raw_creation_date, list):
                # Filter datetimes and select the earliest (oldest) one
                dt_list = [d for d in raw_creation_date if isinstance(d, datetime.datetime)]
                if dt_list:
                    resolved_date = min(dt_list)
            elif isinstance(raw_creation_date, datetime.datetime):
                resolved_date = raw_creation_date
            
            if resolved_date:
                # Remove timezone info for subtraction
                naive_date = resolved_date.replace(tzinfo=None)
                creation_date = naive_date.strftime("%Y-%m-%d")
                age_days = (now - naive_date).days
                lookup_success = True
        except Exception:
            # WHOIS lookup failed
            pass
            
        if lookup_success and age_days is not None:
            if age_days < 30:
                score += 20
                explanation.append(
                    f"Domain '{domain}' is extremely new ({age_days} days old, created on {creation_date})"
                )
            elif 30 <= age_days <= 180:
                score += 10
                explanation.append(
                    f"Domain '{domain}' is moderately new ({age_days} days old, created on {creation_date})"
                )
            else:
                # Legitimate age (older than 180 days)
                pass
        else:
            # Lookup failed or creation date not available
            score += 10
            explanation.append(
                f"WHOIS lookup failed or creation date unavailable for domain '{domain}' (unverifiable age)"
            )
            
        domains_checked.append({
            "domain": domain,
            "age_days": age_days,
            "creation_date": creation_date
        })
        
    return {
        "domains_checked": domains_checked,
        "score": score,
        "explanation": explanation
    }
