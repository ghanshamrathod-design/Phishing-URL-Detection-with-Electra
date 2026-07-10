import base64
import re
from googleapiclient.discovery import build
import google.auth.credentials


class _StaticCredentials(google.auth.credentials.Credentials):
    """Minimal credentials wrapper that holds a bare access token
    and never attempts a refresh."""

    def __init__(self, token):
        super().__init__()
        self.token = token

    def refresh(self, request):
        pass  # no-op: we only have an access token, no refresh token

    @property
    def valid(self):
        return bool(self.token)


def fetch_emails(access_token: str, max_results: int) -> list[dict]:
    """
    Fetch emails from the user's Gmail inbox.

    Args:
        access_token: The user's Google OAuth access token.
        max_results: Number of emails to fetch (20, 50, or 100).

    Returns:
        A list of email dictionaries containing id, subject, sender,
        date, body, urls, and attachments.
    """
    if max_results not in (20, 50, 100):
        raise ValueError("max_results must be 20, 50, or 100")

    try:
        # Use a static credential that skips refresh entirely
        credentials = _StaticCredentials(token=access_token)
        service = build("gmail", "v1", credentials=credentials)

        # Fetch list of message IDs from inbox
        results = (
            service.users()
            .messages()
            .list(userId="me", maxResults=max_results, labelIds=["INBOX"])
            .execute()
        )

        messages = results.get("messages", [])
        if not messages:
            return []

        emails = []

        for msg_ref in messages:
            try:
                # Fetch full message details
                msg = (
                    service.users()
                    .messages()
                    .get(userId="me", id=msg_ref["id"], format="full")
                    .execute()
                )

                email_data = _parse_message(msg)
                emails.append(email_data)

            except Exception as e:
                # Skip individual messages that fail to parse
                emails.append({
                    "id": msg_ref.get("id", "unknown"),
                    "subject": "",
                    "sender": "",
                    "date": "",
                    "body": "",
                    "urls": [],
                    "attachments": [],
                    "error": f"Failed to parse message: {str(e)}",
                })

        return emails

    except Exception as e:
        raise RuntimeError(f"Failed to fetch emails: {str(e)}") from e


def _parse_message(msg: dict) -> dict:
    """Parse a full Gmail message into a structured dictionary."""
    headers = msg.get("payload", {}).get("headers", [])

    subject = _get_header(headers, "Subject")
    sender = _get_header(headers, "From")
    date = _get_header(headers, "Date")

    body = _extract_body(msg.get("payload", {}))
    urls = _extract_urls(body)
    attachments = _extract_attachments(msg.get("payload", {}))

    return {
        "id": msg.get("id", ""),
        "subject": subject,
        "sender": sender,
        "date": date,
        "body": body,
        "urls": urls,
        "attachments": attachments,
    }


def _get_header(headers: list[dict], name: str) -> str:
    """Get a specific header value by name."""
    for header in headers:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", "")
    return ""


def _extract_body(payload: dict) -> str:
    """
    Extract the plain text body from the message payload.
    Handles both simple and multipart MIME structures.
    """
    # Simple message with body data directly on the payload
    if payload.get("mimeType") == "text/plain":
        data = payload.get("body", {}).get("data", "")
        if data:
            return _decode_base64(data)

    # Multipart message — recursively search parts
    parts = payload.get("parts", [])
    for part in parts:
        mime_type = part.get("mimeType", "")

        if mime_type == "text/plain":
            data = part.get("body", {}).get("data", "")
            if data:
                return _decode_base64(data)

        # Nested multipart (e.g., multipart/alternative inside multipart/mixed)
        if mime_type.startswith("multipart/"):
            nested_body = _extract_body(part)
            if nested_body:
                return nested_body

    return ""


def _decode_base64(data: str) -> str:
    """Decode a base64url-encoded string to UTF-8 text."""
    try:
        decoded_bytes = base64.urlsafe_b64decode(data)
        return decoded_bytes.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _extract_urls(text: str) -> list[str]:
    """Extract all URLs from the given text using regex."""
    if not text:
        return []
    url_pattern = r"https?://[^\s<>\"'\)\]}]+"
    return re.findall(url_pattern, text)


def _extract_attachments(payload: dict) -> list[str]:
    """Extract attachment filenames from the message payload."""
    attachments = []
    parts = payload.get("parts", [])

    for part in parts:
        filename = part.get("filename", "")
        if filename:
            attachments.append(filename)

        # Check nested parts for attachments
        if part.get("parts"):
            attachments.extend(_extract_attachments(part))

    return attachments
