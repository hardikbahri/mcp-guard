"""Content detectors: prompt injection, sensitive data (PII and secrets) and code-execution payloads.

All rule-based and deterministic, so every decision can be explained in the audit log and tested in CI. Each detector
returns spans (start, end, kind) so the same result drives both blocking and redaction.
"""
import re
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class Hit:
    kind: str      # e.g. "pii:email", "injection:override", "code:shell"
    start: int
    end: int
    weight: int = 1

    def text(self, s: str) -> str:
        return s[self.start:self.end]


# ---------------------------------------------------------------- sensitive data (DLP)

def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


PII_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone": re.compile(r"(?<![\w+])(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"
                        r"|(?<![\w+])(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)"),
    "card": re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)"),
    "ssn": re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
    "aadhaar": re.compile(r"(?<!\d)[2-9]\d{3}[ -]\d{4}[ -]\d{4}(?!\d)"),
    "pan": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
}

SECRET_PATTERNS = {
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "openai_key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    "bearer_token": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "password_assignment": re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key)\s*[:=]\s*\S{6,}"),
}


def find_sensitive(s: str) -> list[Hit]:
    hits = []
    for kind, rx in PII_PATTERNS.items():
        for m in rx.finditer(s):
            if kind == "card" and not _luhn(re.sub(r"\D", "", m.group())):
                continue  # random long numbers (ids, amounts) are not cards
            hits.append(Hit(f"pii:{kind}", m.start(), m.end()))
    for kind, rx in SECRET_PATTERNS.items():
        hits += [Hit(f"secret:{kind}", m.start(), m.end()) for m in rx.finditer(s)]
    return _merge(hits)


# ---------------------------------------------------------------- prompt injection

# (kind, weight, pattern). A text is treated as an injection when the weights of its hits reach the policy threshold,
# so one weak signal (a stray "system prompt" in a complaint) does not block on its own, while a direct override does.
INJECTION_RULES = [
    ("override", 3, r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your|the)\b"
                    r"[^.\n]{0,20}\b(?:instructions?|rules|prompts?|directions|guidelines|system\s+message)"),
    ("new_instructions", 3, r"(?i)\b(?:new|updated|real|actual)\s+instructions?\s*[:\-]"),
    ("role_takeover", 2, r"\b(?:you are now|from now on,? you|act as|pretend to be|roleplay as)\b"),
    ("system_prompt", 2, r"\b(?:system prompt|developer mode|jailbreak|DAN mode|god mode)\b"),
    ("chat_markup", 3, r"<\|im_start\|>|<\|system\|>|\[/?INST\]|<</?SYS>>|^\s*#{2,}\s*(?:system|assistant)\b|^\s*(?:system|assistant)\s*:"),
    ("tool_directive", 2, r"\b(?:call|invoke|use|run|execute)\s+(?:the\s+)?[`'\"]?[a-z_]{3,}[`'\"]?\s+tool\b"),
    ("exfiltration", 3, r"\b(?:send|email|forward|upload|post|exfiltrate|leak)\b[^.\n]{0,60}"
                        r"(?:https?://|\b[\w.-]+@[\w.-]+\.\w+|\bwebhook\b|\ball (?:records|data|customers|files)\b)"),
    ("concealment", 2, r"\b(?:do not|don't|never)\s+(?:tell|inform|mention|reveal|show)\b[^.\n]{0,30}\b(?:user|human|reviewer|anyone)\b"),
    ("label_steer", 2, r"\b(?:label|classify|mark|tag)\s+(?:this|it|the complaint)\b[^.\n]{0,20}\bas\b"),
    ("md_image_exfil", 3, r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^)\s]*=[^)\s]*\)"),
]
_INJECTION = [(k, w, re.compile(p, re.I | re.M)) for k, w, p in INJECTION_RULES]

INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")
BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])")


def find_injection(s: str) -> list[Hit]:
    norm = unicodedata.normalize("NFKC", s)
    hits = []
    if len(norm) == len(s):  # spans line up with the original only when normalisation kept the length
        for kind, w, rx in _INJECTION:
            hits += [Hit(f"injection:{kind}", m.start(), m.end(), w) for m in rx.finditer(norm)]
    else:
        for kind, w, rx in _INJECTION:
            if rx.search(norm):
                hits.append(Hit(f"injection:{kind}", 0, len(s), w))
    hidden = list(INVISIBLE.finditer(s))
    if hidden:  # zero-width or Unicode tag characters hide instructions from people but not from the model
        hits.append(Hit("injection:hidden_unicode", hidden[0].start(), hidden[-1].end(), 3))
    hits += [Hit("injection:encoded_blob", m.start(), m.end(), 1) for m in BASE64_BLOB.finditer(s)]
    return _merge(hits)


def injection_score(hits: list[Hit]) -> int:
    return sum(h.weight for h in hits if h.kind.startswith("injection:"))


# ---------------------------------------------------------------- code execution payloads

CODE_RULES = {
    "shell": r"(?:;|&&|\|\|?)\s*(?:rm|curl|wget|nc|bash|sh|chmod|python3?)\b|\$\([^)]*\)|`[^`]*\b(?:rm|curl|wget|bash|sh)\b[^`]*`",
    "pipe_to_shell": r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:ba)?sh\b",
    "python_exec": r"\b(?:os\.system|subprocess\.\w+|eval|exec|__import__)\s*\(",
    "sql_injection": r"(?:'\s*(?:or|and)\s*'?\d*'?\s*=\s*'?\d*|;\s*(?:drop|delete|truncate|alter)\s+(?:table|database)\b|\bunion\s+select\b)",
    "path_traversal": r"(?:\.\./){2,}|/etc/passwd|\\\\windows\\\\system32",
}
_CODE = {k: re.compile(p, re.I) for k, p in CODE_RULES.items()}


def find_code(s: str) -> list[Hit]:
    return _merge([Hit(f"code:{k}", m.start(), m.end(), 3) for k, rx in _CODE.items() for m in rx.finditer(s)])


# ---------------------------------------------------------------- helpers

def redact(s: str, hits: list[Hit]) -> str:
    """Replace each span with a typed placeholder, e.g. [REDACTED:EMAIL]. An injection is cut together with the rest of
    its sentence, since the words around the trigger phrase are part of the planted instruction."""
    hits = [_sentence(s, h) if h.kind.startswith("injection:") else h for h in hits]
    hits = _merge_overlaps(hits)
    out, pos = [], 0
    for h in hits:
        tag = h.kind.split(":", 1)[1].upper()
        label = "REMOVED:INJECTION" if h.kind.startswith("injection:") else f"REDACTED:{tag}"
        out += [s[pos:h.start], f"[{label}]"]
        pos = h.end
    out.append(s[pos:])
    return "".join(out)


_SENTENCE_END = re.compile(r"[.!?\n]")


def _sentence(s: str, h: Hit) -> Hit:
    start = max((m.end() for m in _SENTENCE_END.finditer(s, 0, h.start)), default=0)
    m = _SENTENCE_END.search(s, h.end)
    end = m.end() if m else len(s)
    while start < h.start and s[start].isspace():
        start += 1
    return Hit(h.kind, start, end, h.weight)


def _merge_overlaps(hits: list[Hit]) -> list[Hit]:
    """Join overlapping spans; an injection span wins over data found inside it."""
    out: list[Hit] = []
    for h in sorted(hits, key=lambda h: h.start):
        if out and h.start < out[-1].end:
            prev = out[-1]
            kind = prev.kind if prev.kind.startswith("injection:") or not h.kind.startswith("injection:") else h.kind
            out[-1] = Hit(kind, prev.start, max(prev.end, h.end), max(prev.weight, h.weight))
        else:
            out.append(h)
    return out


def _merge(hits: list[Hit]) -> list[Hit]:
    """Drop hits fully inside another hit of the same family (a phone number inside a card number, and so on)."""
    hits = sorted(hits, key=lambda h: (h.start, -(h.end - h.start)))
    kept: list[Hit] = []
    for h in hits:
        fam = h.kind.split(":")[0]
        if any(k.start <= h.start and h.end <= k.end and k.kind.split(":")[0] == fam for k in kept):
            continue
        kept.append(h)
    return kept


def strings_in(obj, path=""):
    """Yield (path, string) for every string inside nested dicts/lists, so arguments and results are scanned whole."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from strings_in(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from strings_in(v, f"{path}[{i}]")


def map_strings(obj, fn):
    """Return a copy of obj with fn applied to every string."""
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, dict):
        return {k: map_strings(v, fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [map_strings(v, fn) for v in obj]
    if isinstance(obj, tuple):
        return tuple(map_strings(v, fn) for v in obj)
    return obj
