from phishing_detector.keyword_detector import check_keywords
from phishing_detector.url_detector import check_urls
from phishing_detector.typosquat_detector import check_typosquatting
from phishing_detector.domain_reputation import check_domain_reputation
from phishing_detector.spf_dmarc_checker import check_spf_dmarc
from phishing_detector.attachment_checker import check_attachments
from phishing_detector.sender_analyzer import check_sender


def analyze(text: str, sender_domain: str = None, sender_email: str = None, attachments: list = None) -> dict:
    """
    Runs all phishing detectors on the provided input and returns a combined
    risk assessment.

    Args:
        text (str): The message or email body to analyze.
        sender_domain (str, optional): The sender's email domain (e.g. "google.com").
        sender_email (str, optional): The full sender string (e.g. "Amazon Support <orders@amaz0n.com>").
        attachments (list, optional): List of attachment filenames to check.

    Returns:
        A dictionary with:
            score (int): Final capped risk score (0-100)
            verdict (str): "Safe", "Suspicious", or "High Risk"
            category (str): Type of threat detected
            summary (str): Natural language summary of findings
            reasons (list[str]): Combined explanations from all detectors
            details (dict): Raw results from each individual detector
    """
    if not isinstance(text, str):
        text = ""
    if attachments is None:
        attachments = []

    raw_score = 0
    reasons = []
    details = {}

    # --- Run keyword detector ---
    keyword_result = check_keywords(text, sender=sender_email)
    raw_score += keyword_result["score"]
    reasons.extend(keyword_result["explanation"])
    details["keywords"] = keyword_result

    # --- Run URL detector ---
    url_result = check_urls(text)
    raw_score += url_result["score"]
    reasons.extend(url_result["explanation"])
    details["urls"] = url_result

    # --- Run typosquatting detector (now also checks sender email domain) ---
    typo_result = check_typosquatting(text, sender_email=sender_email)
    raw_score += typo_result["score"]
    reasons.extend(typo_result["explanation"])
    details["typosquatting"] = typo_result

    # --- Run domain reputation detector ---
    domain_rep_result = check_domain_reputation(text)
    raw_score += domain_rep_result["score"]
    reasons.extend(domain_rep_result["explanation"])
    details["domain_reputation"] = domain_rep_result

    # --- Run SPF/DMARC checker (only if sender_domain is provided) ---
    if sender_domain and isinstance(sender_domain, str) and sender_domain.strip():
        spf_result = check_spf_dmarc(sender_domain.strip())
        raw_score += spf_result["score"]
        reasons.extend(spf_result["explanation"])
        details["spf_dmarc"] = spf_result
    else:
        details["spf_dmarc"] = None

    # --- Run attachment checker ---
    attachment_result = check_attachments(attachments)
    raw_score += attachment_result["score"]
    reasons.extend(attachment_result["explanation"])
    details["attachments"] = attachment_result

    # --- Run sender analyzer ---
    if sender_email and isinstance(sender_email, str) and sender_email.strip():
        sender_result = check_sender(sender_email.strip())
        raw_score += sender_result["score"]
        reasons.extend(sender_result["explanation"])
        details["sender_analysis"] = sender_result
    else:
        details["sender_analysis"] = None

    # --- Cap score at 100 ---
    score = min(raw_score, 100)

    # --- Determine verdict ---
    if score <= 20:
        verdict = "Safe"
    elif score <= 50:
        verdict = "Suspicious"
    else:
        verdict = "High Risk"

    # --- Determine category (priority order matters) ---
    found_keywords = keyword_result.get("found_keywords", [])
    typo_found = typo_result.get("found", [])
    dangerous_files = attachment_result.get("dangerous_files", [])
    sender_flags = (
        details.get("sender_analysis", {}).get("flags", [])
        if details.get("sender_analysis") else []
    )

    banking_keywords = {"bank", "password", "account blocked"}
    urgency_keywords = {"urgent", "verify", "immediate action", "limited time"}

    has_banking = bool(banking_keywords & set(found_keywords))
    has_urgency = bool(urgency_keywords & set(found_keywords))
    has_sender_spoofing = bool(
        {"Display name spoofing", "Suspicious sender domain", "Free email provider impersonation"}
        & set(sender_flags)
    )

    if has_sender_spoofing:
        category = "Sender Spoofing"
    elif typo_found:
        category = "Credential Harvesting"
    elif dangerous_files:
        category = "Malware Distribution"
    elif has_banking:
        category = "Banking Scam"
    elif has_urgency:
        category = "Phishing Attempt"
    else:
        category = "Suspicious Activity"

    # --- Generate natural language summary ---
    summary_parts = []

    if has_sender_spoofing:
        summary_parts.append(
            "The sender of this message appears to be impersonating a legitimate brand. "
            "The email address does not match the claimed identity."
        )

    if typo_found:
        brands = list({entry["impersonating"] for entry in typo_found})
        brands_str = ", ".join(brands[:3])
        summary_parts.append(f"This message impersonates a legitimate brand ({brands_str}) and may attempt to steal credentials.")

    if dangerous_files:
        summary_parts.append(
            f"This email contains dangerous attachments ({', '.join(dangerous_files[:3])}) "
            f"that may distribute malware."
        )

    if has_urgency and url_result.get("urls_found"):
        summary_parts.append(
            "This message contains urgency language and suspicious URLs that may indicate a phishing attempt."
        )
    elif has_urgency:
        summary_parts.append("This message uses urgency language to pressure the recipient into acting quickly.")

    if has_banking:
        summary_parts.append("This message references banking or credential-related terms that are common in financial scams.")

    spf_res = details.get("spf_dmarc")
    if spf_res and (spf_res.get("spf_status") == "FAIL" or spf_res.get("dmarc_status") == "FAIL"):
        summary_parts.append(
            f"The sender domain lacks proper email authentication (SPF: {spf_res['spf_status']}, "
            f"DMARC: {spf_res['dmarc_status']}), which is a common indicator of email spoofing."
        )

    if not summary_parts:
        if score == 0:
            summary_parts.append("No significant phishing signals were detected in this message.")
        else:
            summary_parts.append("This message contains some suspicious signals that warrant caution.")

    summary = " ".join(summary_parts)

    return {
        "score": score,
        "verdict": verdict,
        "category": category,
        "summary": summary,
        "reasons": reasons,
        "details": details
    }
