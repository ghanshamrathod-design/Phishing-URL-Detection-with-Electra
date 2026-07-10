import re
from urllib.parse import urlparse

def check_urls(text: str) -> dict:
    """
    Extracts all URLs from the input text and analyzes them for suspicious phishing signals.
    
    Checks per URL:
    1. HTTP scheme instead of HTTPS (+20 score)
    2. Shortened URL domain (+20 score)
    3. More than 3 dots in the domain (+10 score)
    4. URL length > 75 characters (+10 score)
    5. Suspicious special characters (@, %, --) (+10 score)
    
    Returns a dictionary:
    {
        "urls_found": list[str],
        "score": int,
        "flags": list[str],
        "explanation": list[str]
    }
    """
    if not isinstance(text, str):
        return {
            "urls_found": [],
            "score": 0,
            "flags": ["invalid_input"],
            "explanation": ["Invalid input: text must be a string."]
        }
    
    # Regular expression to extract URLs starting with http:// or https://
    # This matches non-whitespace characters after the scheme
    url_pattern = r'https?://[^\s<>"]+'
    urls_found = re.findall(url_pattern, text)
    
    # Deduplicate while preserving order
    unique_urls = []
    for u in urls_found:
        if u not in unique_urls:
            unique_urls.append(u)
            
    score = 0
    flags = []
    explanation = []
    
    shortened_domains = {
        "bit.ly", 
        "tinyurl.com", 
        "t.co", 
        "goo.gl", 
        "ow.ly", 
        "shorturl.at"
    }
    
    for url in unique_urls:
        try:
            parsed = urlparse(url)
            # Normalize domain (remove port if any, lowercase it)
            domain = parsed.netloc.split(':')[0].lower()
        except Exception:
            domain = ""
        
        # 1. Insecure scheme (http)
        if url.startswith("http://"):
            score += 20
            flags.append(f"insecure_scheme:{url}")
            explanation.append(f"Insecure scheme (HTTP instead of HTTPS) detected: {url}")
            
        # 2. Shortened URL
        if domain in shortened_domains:
            score += 20
            flags.append(f"shortened_url:{url}")
            explanation.append(f"Shortened URL domain ({domain}) detected: {url}")
            
        # 3. Excessive dots in domain (> 3 dots)
        if domain.count('.') > 3:
            score += 10
            flags.append(f"excessive_domain_dots:{url}")
            explanation.append(f"Excessive dots in domain ({domain.count('.')}) detected: {url}")
            
        # 4. Long URL (> 75 characters)
        if len(url) > 75:
            score += 10
            flags.append(f"long_url:{url}")
            explanation.append(f"URL exceeds 75 characters ({len(url)} chars): {url}")
            
        # 5. Suspicious special characters (@, %, --)
        special_chars_found = []
        if '@' in url:
            special_chars_found.append('@')
        if '%' in url:
            special_chars_found.append('%')
        if '--' in url:
            special_chars_found.append('--')
            
        if special_chars_found:
            score += 10
            flags.append(f"suspicious_characters:{url}")
            chars_str = ", ".join(special_chars_found)
            explanation.append(f"Suspicious special characters ({chars_str}) detected in URL: {url}")
            
    return {
        "urls_found": unique_urls,
        "score": score,
        "flags": flags,
        "explanation": explanation
    }
