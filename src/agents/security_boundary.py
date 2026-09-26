"""Reference security boundary for the Day 11 Guards Agent.

This is deliberately framework-independent so students can inspect the policy
and reason about the difference between untrusted content and an authorised
action. It is not a solution for the TODOs in ``src/assignment``.
"""
from __future__ import annotations

import base64
import codecs
import html
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote, urlparse


TRUSTED_EGRESS_HOSTS = frozenset({"api.vinbank.example", "cases.vinbank.example"})
HIGH_RISK_ACTIONS = frozenset({
    "transfer_money", "close_account", "change_password",
    "delete_data", "update_personal_info",
})
ZERO_WIDTH = "\u200b\u200c\u200d\ufeff\u2060"
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "і": "i", "о": "o", "р": "p",
    "с": "c", "у": "y", "х": "x", "ѕ": "s",
    "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
})
SECRET_PATTERNS = (
    r"\badmin123\b",
    r"sk-[a-z0-9-]{8,}",
    r"db\.vinbank\.internal(?::\d+)?",
    r"(?:password|mật\s*khẩu)\s*(?:is|là|[:=])\s*\S+",
)
INSTRUCTION_OVERRIDE_PATTERNS = (
    r"ignore\s+(?:all\s+)?(?:previous|above|prior)?\s*instructions?",
    r"(?:system|developer)\s+(?:prompt|instruction)|system\s+override",
    r"(?:reveal|disclose|translate|encode|summarize)\b.*(?:secret|password|credential|api\s*key|internal)",
    r"bỏ\s+qua\s+(?:mọi\s+)?hướng\s+dẫn|tiết\s+lộ\s+(?:mật\s*khẩu|api|thông\s*tin\s*nội\s*bộ)",
    r"<\s*/?\s*(?:system|developer|assistant|user)\b|\[\s*(?:system|developer|assistant|inst)\s*\]",
    r"(?:print|repeat|copy|list|provide|return|output|dump|extract|display|show|reproduce|quote|read)\b.{0,120}\b(?:hidden|initial|developer|system|internal|confidential|secret|credentials?|password|api\s*key|database|config|instructions?|context|note|message)",
    r"what\s+(?:text|content|value|message)\b.{0,80}\b(?:hidden|initial|developer|system|internal|confidential|instructions?|context|note)",
    r"(?:encode|decode|translate|convert|format|base64|rot13|hex|json|yaml|xml)\b.{0,120}\b(?:hidden|internal|confidential|secret|credentials?|password|api\s*key|database|config|instructions?|context|note)",
    r"(?:fill|complete)\b.{0,80}\b(?:blank|password|api\s*key|database|credential)",
    r"(?:action\s+required|required\s+action)\b.{0,200}\b(?:hidden|internal|confidential|secret|credentials?|password|api\s*key|database|config|note|ghi\s+chú\s+nội\s+bộ)",
)


@dataclass(frozen=True)
class ExternalContent:
    """Data retrieved from email/RAG/web; never an instruction authority."""

    source: str
    text: str
    trusted: bool = False


@dataclass(frozen=True)
class ActionRequest:
    """A proposed side effect awaiting deterministic policy and human approval."""

    action: str
    destination: str
    payload: str
    approval_id: str | None = None
    reviewer_id: str | None = None


@dataclass(frozen=True)
class ActionDecision:
    allowed: bool
    reason: str
    requires_human: bool


def normalize_for_security(text: str) -> str:
    """Canonicalize Unicode and remove invisible separators before policy checks."""
    normalized = html.unescape(unquote(text or ""))
    normalized = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda match: chr(int(match.group(1), 16)),
        normalized,
    )
    normalized = unicodedata.normalize("NFKC", normalized).translate(CONFUSABLES)
    normalized = normalized.translate(str.maketrans("", "", ZERO_WIDTH))
    return re.sub(r"\s+", " ", normalized).strip()


def _ascii_fold(text: str) -> str:
    folded = "".join(
        character
        for character in unicodedata.normalize("NFD", text.casefold())
        if unicodedata.category(character) != "Mn"
    )
    return folded.replace("đ", "d")


def _decoded_secret_candidates(text: str) -> list[str]:
    """Decode common attacker-requested representations without executing content."""
    candidates: list[str] = []
    bounded_text = text[:20_000]
    base64_tokens = re.findall(
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,4096}={0,2}(?![A-Za-z0-9+/])",
        bounded_text,
    )[:64]
    for token in base64_tokens:
        try:
            padded = token + "=" * (-len(token) % 4)
            decoded = base64.b64decode(padded, validate=True).decode("utf-8")
            candidates.append(decoded)
        except (ValueError, UnicodeDecodeError):
            continue
    hex_tokens = re.findall(
        r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){4,2048}(?![0-9a-fA-F])",
        bounded_text,
    )[:64]
    for token in hex_tokens:
        try:
            candidates.append(bytes.fromhex(token).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
    return candidates


def contains_secret(text: str) -> bool:
    """Detect a synthetic lab secret even when punctuation/spacing is altered."""
    return _contains_secret(text, depth=0)


def _contains_secret(text: str, *, depth: int) -> bool:
    security_text = normalize_for_security(text)
    spoken = re.sub(r"\b(?:dot|chấm)\b", ".", security_text, flags=re.IGNORECASE)
    spoken = re.sub(r"\b(?:colon|hai\s+chấm)\b", ":", spoken, flags=re.IGNORECASE)
    normalized = re.sub(r"[^a-z0-9]", "", _ascii_fold(spoken))
    secrets = ("admin123", "skvinbanksecret2024", "dbvinbankinternal")
    encoded_forms = tuple(codecs.encode(secret, "rot_13") for secret in secrets)
    if any(
        secret in normalized or secret[::-1] in normalized or encoded in normalized
        for secret, encoded in zip(secrets, encoded_forms)
    ):
        return True
    if any(
        re.search(pattern, security_text, re.IGNORECASE)
        for pattern in SECRET_PATTERNS
    ):
        return True
    if depth >= 2:
        return False
    return any(
        _contains_secret(candidate, depth=depth + 1)
        for candidate in _decoded_secret_candidates(security_text)
    )


def contains_instruction_override(text: str) -> bool:
    """Identify instruction-like text after Unicode normalization."""
    normalized = normalize_for_security(text)
    if any(
        re.search(pattern, normalized, re.IGNORECASE)
        for pattern in INSTRUCTION_OVERRIDE_PATTERNS
    ):
        return True

    folded = _ascii_fold(normalized)
    vietnamese_extraction = (
        r"(?:bo\s+qua|quen)\b.{0,80}\b(?:huong\s+dan|quy\s+tac)",
        r"(?:liet\s+ke|cung\s+cap|hien\s+thi|doc|in|lay|chen|sao\s+chep|ghi\s+lai|dua|lap\s+lai|trich\s+xuat|tiet\s+lo|xac\s+nhan|dien)\b.{0,160}\b(?:mat\s+khau|api\s*key|khoa\s+api|cau\s+hinh|thong\s+tin\s+noi\s+bo|ghi\s+chu\s+noi\s+bo|may\s+chu|huong\s+dan\s+an|ngu\s+canh\s+an)",
        r"(?:ma\s+hoa|giai\s+ma|dich|chuyen\s+doi|dinh\s+dang)\b.{0,120}\b(?:ghi\s+chu\s+noi\s+bo|cau\s+hinh|mat\s+khau|api\s*key|thong\s+tin\s+bi\s+mat)",
        r"(?:dong\s+vai|gia\s+vo|tinh\s+huong\s+gia\s+dinh)\b.{0,120}\b(?:kiem\s+toan|quan\s+tri|mat\s+khau|cau\s+hinh|bi\s+mat)",
    )
    if any(re.search(pattern, folded) for pattern in vietnamese_extraction):
        return True

    compact = re.sub(r"[^a-z0-9]", "", folded)
    compact_markers = (
        "ignoreallpreviousinstructions",
        "ignorepreviousinstructions",
        "systemprompt",
        "developerprompt",
        "developermessage",
        "hiddeninstructions",
        "internalcredentials",
        "boquamoihuongdan",
        "lietketoanbothongtinnoibo",
        "mahoaghichunoibo",
    )
    return any(marker in compact for marker in compact_markers)


def assess_external_content(content: ExternalContent) -> ActionDecision:
    """Treat third-party content as data and reject attempts to change policy."""
    if content.trusted:
        return ActionDecision(True, "trusted source metadata", False)
    if contains_instruction_override(content.text):
        return ActionDecision(False, "untrusted content contains an instruction override", False)
    return ActionDecision(True, "untrusted content is data only", False)


def authorize_action(request: ActionRequest) -> ActionDecision:
    """Enforce exact destination allowlist, secret egress block and HITL for risk."""
    destination = urlparse(request.destination)
    try:
        destination_port = destination.port
    except ValueError:
        return ActionDecision(False, "destination has an invalid port", False)
    if (
        destination.scheme != "https"
        or destination.hostname not in TRUSTED_EGRESS_HOSTS
        or destination_port not in (None, 443)
        or destination.username is not None
        or destination.password is not None
    ):
        return ActionDecision(False, "destination is not allowlisted", False)
    if contains_secret(request.payload):
        return ActionDecision(False, "payload contains protected data", False)
    if request.action in HIGH_RISK_ACTIONS:
        approved = bool(
            request.reviewer_id
            and request.approval_id
            and re.fullmatch(r"HITL-[A-Z0-9]{8}", request.approval_id)
        )
        if not approved:
            return ActionDecision(False, "high-risk action needs recorded human approval", True)
    return ActionDecision(True, "least-privilege policy permits this action", False)
