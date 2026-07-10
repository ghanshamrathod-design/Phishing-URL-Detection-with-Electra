import re
from urllib.parse import urlparse
import Levenshtein

def check_typosquatting(text: str, sender_email: str = None) -> dict:
    """
    Extracts domains from URLs in the input text, and compares each domain 
    against a list of legitimate brands using Levenshtein distance.
    
    Optionally accepts a sender_email parameter. If provided, the domain
    is extracted from the email (everything after @) and also checked
    against the brand list for typosquatting.
    
    Legitimate brands checked:
    google.com, amazon.com, paypal.com, netflix.com, microsoft.com, 
    apple.com, facebook.com, instagram.com, twitter.com, linkedin.com, 
    youtube.com, gmail.com, yahoo.com, bankofamerica.com, chase.com
    
    If the Levenshtein distance between an extracted domain and a brand is 
    between 1 and 3 (inclusive), it is flagged as typosquatting (+30 score).
    
    Returns a dictionary:
    {
        "found": list[dict],
        "score": int,
        "explanation": list[str]
    }
    """
    if not isinstance(text, str):
        return {
            "found": [],
            "score": 0,
            "explanation": ["Invalid input: text must be a string."]
        }
        
    legitimate_brands = [
        "google.com", 
        "amazon.com", 
        "paypal.com", 
        "netflix.com", 
        "microsoft.com", 
        "apple.com", 
        "facebook.com", 
        "instagram.com", 
        "twitter.com", 
        "linkedin.com", 
        "youtube.com", 
        "gmail.com", 
        "yahoo.com", 
        "bankofamerica.com", 
        "chase.com"
    ]
    
    # Extract URLs starting with http:// or https://
    url_pattern = r'https?://[^\s<>""]+'
    urls_found = re.findall(url_pattern, text)
    
    # Extract and normalize unique domains
    unique_domains = []
    for url in urls_found:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0].lower()
            if domain and domain not in unique_domains:
                unique_domains.append(domain)
        except Exception:
            continue
            
    found = []
    score = 0
    explanation = []
    
    # --- Check URL domains ---
    for domain in unique_domains:
        # Strip leading 'www.' if present, to check root domain typosquatting
        domain_to_check = domain
        if domain_to_check.startswith("www."):
            domain_to_check = domain_to_check[4:]
            
        for brand in legitimate_brands:
            dist = Levenshtein.distance(domain_to_check, brand)
            if 1 <= dist <= 3:
                # Flag as typosquatting
                found.append({
                    "domain": domain,
                    "impersonating": brand,
                    "source": "url"
                })
                score += 30
                explanation.append(
                    f"Possible typosquatting: Domain '{domain}' is very close to legitimate brand '{brand}' (Levenshtein distance: {dist})"
                )
                # Break to avoid flagging the same domain multiple times for different brands
                break
    
    # --- Check sender email domain ---
    if sender_email and isinstance(sender_email, str) and "@" in sender_email:
        sender_domain = sender_email.split("@")[-1].strip().lower()
        # Strip leading 'www.' if present
        if sender_domain.startswith("www."):
            sender_domain = sender_domain[4:]
        
        for brand in legitimate_brands:
            dist = Levenshtein.distance(sender_domain, brand)
            if 1 <= dist <= 3:
                found.append({
                    "domain": sender_domain,
                    "impersonating": brand,
                    "source": "sender_email"
                })
                score += 30
                explanation.append(
                    f"Sender domain typosquatting: Sender domain '{sender_domain}' is very close to legitimate brand '{brand}' (Levenshtein distance: {dist})"
                )
                break
                
    return {
        "found": found,
        "score": score,
        "explanation": explanation
    }
