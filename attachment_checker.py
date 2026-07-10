import os

def check_attachments(filenames: list) -> dict:
    """
    Checks a list of filenames for dangerous file extensions that are
    commonly used in phishing attacks and malware distribution.

    Dangerous extensions flagged:
    exe, scr, bat, cmd, js, vbs, ps1, jar, com, pif, reg, msi, hta, wsf

    Each dangerous file found adds 30 to the score.

    Args:
        filenames: A list of filename strings to check.

    Returns:
        A dictionary with:
            dangerous_files (list[str]): Filenames with dangerous extensions
            score (int): Total risk score
            explanation (list[str]): Human-readable findings
    """
    if not isinstance(filenames, list):
        return {
            "dangerous_files": [],
            "score": 0,
            "explanation": ["Invalid input: filenames must be a list."]
        }

    dangerous_extensions = {
        "exe", "scr", "bat", "cmd", "js", "vbs",
        "ps1", "jar", "com", "pif", "reg", "msi", "hta", "wsf"
    }

    dangerous_files = []
    score = 0
    explanation = []

    for filename in filenames:
        if not isinstance(filename, str):
            continue

        # Extract extension, strip leading dot, lowercase for comparison
        _, ext = os.path.splitext(filename)
        ext_clean = ext.lstrip(".").lower()

        if ext_clean in dangerous_extensions:
            dangerous_files.append(filename)
            score += 30
            explanation.append(
                f"Dangerous attachment detected: '{filename}' has a high-risk extension (.{ext_clean})"
                )

    return {
        "dangerous_files": dangerous_files,
        "score": score,
        "explanation": explanation
    }
