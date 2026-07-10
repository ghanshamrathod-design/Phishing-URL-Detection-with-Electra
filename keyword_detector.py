def _normalize_leet_speak(text: str) -> str:
    """
    Replaces common leet speak substitutions to normalize text
    before keyword matching.
    """
    leet_map = {
        "0": "o",
        "1": "i",
        "@": "a",
        "3": "e",
        "$": "s",
        "4": "a",
    }
    for leet_char, normal_char in leet_map.items():
        text = text.replace(leet_char, normal_char)
    return text


# Legitimate sender domains that reduce false positives
WHITELISTED_DOMAINS = [
    "linkedin.com",
    "google.com",
    "github.com",
    "kaggle.com",
]

WHITELIST_SCORE_REDUCTION = 20


def check_keywords(text: str, sender: str = None) -> dict:
    """
    Checks a string of text for suspicious phishing-related keywords.
    
    Text is first normalized to defeat leet speak obfuscation
    (0→o, 1→i, @→a, 3→e, $→s, 4→a).
    
    If the sender context contains a whitelisted domain (e.g. linkedin.com,
    google.com, github.com, kaggle.com), the score is reduced by 20 to
    lower false positives.
    
    Suspicious words checked:
    verify, urgent, reward, bank, password, suspended, limited time, 
    winner, congratulations, click here, free, account blocked, immediate action,
    wire transfer, cryptocurrency, bitcoin, gift card, western union,
    inheritance, lottery, prize, claim your.
    
    Returns a dictionary:
    {
        "found_keywords": list[str],
        "score": int,
        "whitelisted": bool,
        "explanation": list[str]
    }
    """
    if not isinstance(text, str):
        return {
            "found_keywords": [],
            "score": 0,
            "whitelisted": False,
            "explanation": ["Invalid input: text must be a string."]
        }
        
    # Normalize leet speak then lowercase for case-insensitive checking
    text_normalized = _normalize_leet_speak(text.lower())
    
    # Suspicious keywords mapped to their description categories
    suspicious_keywords = {
        "verify": "Verification/Credential word",
        "urgent": "Urgency word",
        "reward": "Offer/Reward word",
        "bank": "Financial/Bank keyword",
        "password": "Credential word",
        "suspended": "Account status word",
        "limited time": "Urgency/Scarcity word",
        "winner": "Reward/Winner keyword",
        "congratulations": "Reward/Congratulations keyword",
        "click here": "Call-to-action link",
        "free": "Offer word",
        "account blocked": "Account status word",
        "immediate action": "Urgency/Immediate action word",
        "wire transfer": "Financial/Wire transfer keyword",
        "cryptocurrency": "Financial/Cryptocurrency keyword",
        "bitcoin": "Financial/Bitcoin keyword",
        "gift card": "Financial/Gift card keyword",
        "western union": "Financial/Wire service keyword",
        "inheritance": "Scam/Inheritance keyword",
        "lottery": "Scam/Lottery keyword",
        "prize": "Scam/Prize keyword",
        "claim your": "Scam/Claim keyword",
    }
    
    found_keywords = []
    score = 0
    explanation = []
    
    for keyword, category in suspicious_keywords.items():
        if keyword in text_normalized:
            found_keywords.append(keyword)
            score += 10
            explanation.append(f"{category} detected: {keyword}")
    
    # --- Whitelist check to reduce false positives ---
    whitelisted = False
    if sender and isinstance(sender, str):
        sender_lower = sender.lower()
        for domain in WHITELISTED_DOMAINS:
            if domain in sender_lower:
                whitelisted = True
                score = max(score - WHITELIST_SCORE_REDUCTION, 0)
                explanation.append(
                    f"Whitelisted sender domain detected ({domain}): "
                    f"score reduced by {WHITELIST_SCORE_REDUCTION}"
                )
                break
            
    return {
        "found_keywords": found_keywords,
        "score": score,
        "whitelisted": whitelisted,
        "explanation": explanation
    }
