import dns.resolver

def check_spf_dmarc(domain: str) -> dict:
    """
    Checks the SPF and DMARC DNS records for a given email domain.

    SPF Check:
    - Queries TXT records of the domain.
    - If a record starting with "v=spf1" is found, SPF status is PASS.
    - If no SPF record is found, SPF status is FAIL and adds 20 to score.
    - If the DNS query fails, SPF status is UNKNOWN and adds 20 to score.

    DMARC Check:
    - Queries TXT records of _dmarc.<domain>.
    - If a record starting with "v=DMARC1" is found, DMARC status is PASS.
    - If no DMARC record is found, DMARC status is FAIL and adds 10 to score.
    - If the DNS query fails, DMARC status is UNKNOWN and adds 10 to score.

    Args:
        domain: The email domain to check (e.g. "google.com").

    Returns:
        A dictionary with:
            spf_status (str): "PASS", "FAIL", or "UNKNOWN"
            dmarc_status (str): "PASS", "FAIL", or "UNKNOWN"
            score (int): Total risk score
            explanation (list[str]): Human-readable findings
    """
    if not isinstance(domain, str) or not domain.strip():
        return {
            "spf_status": "UNKNOWN",
            "dmarc_status": "UNKNOWN",
            "score": 0,
            "explanation": ["Invalid input: domain must be a non-empty string."]
        }

    domain = domain.strip().lower()
    score = 0
    explanation = []

    # --- SPF Check ---
    spf_status = "UNKNOWN"
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        spf_found = False
        for rdata in answers:
            # TXT records can be split across multiple strings; join them
            record = "".join(part.decode("utf-8") for part in rdata.strings)
            if record.startswith("v=spf1"):
                spf_found = True
                spf_status = "PASS"
                explanation.append(f"SPF record found for '{domain}': {record[:80]}{'...' if len(record) > 80 else ''}")
                break
        if not spf_found:
            spf_status = "FAIL"
            score += 20
            explanation.append(f"No SPF record found for domain '{domain}' — email spoofing risk is higher.")
    except dns.resolver.NXDOMAIN:
        spf_status = "FAIL"
        score += 20
        explanation.append(f"Domain '{domain}' does not exist (NXDOMAIN) — SPF check failed.")
    except dns.resolver.NoAnswer:
        spf_status = "FAIL"
        score += 20
        explanation.append(f"No TXT records found for domain '{domain}' — SPF check failed.")
    except Exception as e:
        spf_status = "UNKNOWN"
        score += 20
        explanation.append(f"SPF DNS lookup failed for domain '{domain}': {type(e).__name__}.")

    # --- DMARC Check ---
    dmarc_status = "UNKNOWN"
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        dmarc_found = False
        for rdata in answers:
            record = "".join(part.decode("utf-8") for part in rdata.strings)
            if record.startswith("v=DMARC1"):
                dmarc_found = True
                dmarc_status = "PASS"
                explanation.append(f"DMARC record found for '{domain}': {record[:80]}{'...' if len(record) > 80 else ''}")
                break
        if not dmarc_found:
            dmarc_status = "FAIL"
            score += 10
            explanation.append(f"No DMARC record found for domain '{domain}' — phishing protection is weaker.")
    except dns.resolver.NXDOMAIN:
        dmarc_status = "FAIL"
        score += 10
        explanation.append(f"No DMARC record found for domain '{domain}' (NXDOMAIN on _dmarc subdomain) — phishing protection is weaker.")
    except dns.resolver.NoAnswer:
        dmarc_status = "FAIL"
        score += 10
        explanation.append(f"No DMARC TXT records found for domain '{domain}' — phishing protection is weaker.")
    except Exception as e:
        dmarc_status = "UNKNOWN"
        score += 10
        explanation.append(f"DMARC DNS lookup failed for domain '{domain}': {type(e).__name__}.")

    return {
        "spf_status": spf_status,
        "dmarc_status": dmarc_status,
        "score": score,
        "explanation": explanation
    }
