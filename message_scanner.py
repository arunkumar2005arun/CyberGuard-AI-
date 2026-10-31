import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit


_LINK_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
_CATEGORY_RULES: tuple[tuple[str, int, tuple[str, ...], str], ...] = (
    (
        "Phishing language",
        20,
        (
            r"\bverify your (?:account|identity|details)\b",
            r"\bconfirm your (?:account|identity|details)\b",
            r"\bclick (?:the )?link below\b",
            r"\bsign in to (?:restore|unlock|secure)\b",
            r"\bunusual (?:activity|sign[\s-]?in) (?:was )?(?:detected|on your account)\b",
        ),
        "Avoid links in unsolicited messages; open the service using its official app or a "
        "bookmark you already trust.",
    ),
    (
        "Urgency",
        15,
        (
            r"\bact now\b",
            r"\bimmediately\b",
            r"\bwithin \d+ hours?\b",
            r"\burgent(?:ly)?\b",
            r"\bexpires? (?:today|soon|in \d+ hours?)\b",
            r"\bfinal notice\b",
        ),
        "Pause before responding. Urgency is often used to pressure people into unsafe actions.",
    ),
    (
        "Threats or account consequences",
        20,
        (
            r"\baccount (?:will be|has been) (?:suspended|closed|blocked|locked|terminated)\b",
            r"\blegal action\b",
            r"\b(?:arrest|prosecution|penalt(?:y|ies))\b",
            r"\blose access\b",
        ),
        "Verify account or legal claims through an official channel, not through the message.",
    ),
    (
        "Prize or lottery claim",
        20,
        (
            r"\bcongratulations\b",
            r"\byou(?:'ve| have) won\b",
            r"\b(?:winner|won) (?:a |the )?(?:prize|lottery|giveaway)\b",
            r"\bclaim your (?:prize|reward|winnings)\b",
            r"\bfree (?:gift|prize)\b",
        ),
        "Treat unexpected prizes as suspicious. Do not pay a fee or share details to claim them.",
    ),
    (
        "Suspicious offer",
        15,
        (
            r"\bguaranteed (?:income|return|profit|approval)\b",
            r"\blimited[- ]time offer\b",
            r"\bunbelievable discount\b",
            r"\btoo good to be true\b",
            r"\bfree (?:cash|money|voucher)\b",
        ),
        "Research offers independently and avoid sharing payment details to claim an unsolicited deal.",
    ),
    (
        "Sensitive information request",
        25,
        (
            r"\b(?:send|share|provide|reply with|enter) (?:us )?(?:your )?"
            r"(?:password|passcode|one[- ]time (?:code|password)|otp|pin|"
            r"verification code|bank details|card number|security code)\b",
            r"\b(?:password|passcode|one[- ]time (?:code|password)|otp|pin|"
            r"verification code|bank details|card number|security code)\b"
            r".{0,35}\b(?:reply|send|share|provide|enter)\b",
            r"\bconfirm your (?:password|pin|card details|bank details)\b",
        ),
        "Never send passwords, one-time codes, PINs, or full payment details in response to a "
        "message. Contact the organization through a verified channel.",
    ),
)
_SHORTENER_DOMAINS = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly"}
)
_URL_KEYWORDS = ("login", "verify", "password", "account", "secure", "update", "bank")


@dataclass(frozen=True)
class MessageIndicator:
    category: str
    points: int
    evidence: tuple[str, ...]
    explanation: str
    recommendation: str


@dataclass(frozen=True)
class MessageAssessment:
    score: int
    level: str
    indicators: tuple[MessageIndicator, ...]
    links_found: tuple[str, ...]
    suspicious_links: tuple[str, ...]

    @property
    def recommendations(self) -> tuple[str, ...]:
        if not self.indicators:
            return (
                "No configured warning signs were detected. This does not prove the message "
                "is safe; verify unexpected requests through a trusted channel.",
            )
        return tuple(dict.fromkeys(item.recommendation for item in self.indicators))


def _extract_links(message: str) -> tuple[str, ...]:
    links: list[str] = []
    for match in _LINK_PATTERN.finditer(message):
        link = match.group(0).rstrip(".,!?;:)]}")
        if link and link not in links:
            links.append(link)
    return tuple(links)


def _is_suspicious_link(link: str) -> bool:
    candidate = link if "://" in link else f"http://{link}"
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        if not hostname:
            return True
        hostname = hostname.lower().rstrip(".")
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            pass
        if hostname in _SHORTENER_DOMAINS:
            return True
        if parsed.scheme.lower() != "https":
            return True
        return any(keyword in link.lower() for keyword in _URL_KEYWORDS)
    except ValueError:
        return True


def analyze_message(message: str) -> MessageAssessment:
    """Analyze message text with local rules only; links are parsed, never opened."""
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Enter a text message to analyze.")

    links = _extract_links(message)
    suspicious_links = tuple(link for link in links if _is_suspicious_link(link))
    indicators: list[MessageIndicator] = []
    lowered_message = message.lower()

    for category, points, patterns, recommendation in _CATEGORY_RULES:
        evidence = tuple(
            match.group(0)
            for pattern in patterns
            for match in re.finditer(pattern, lowered_message, flags=re.IGNORECASE)
        )
        if evidence:
            indicators.append(
                MessageIndicator(
                    category=category,
                    points=points,
                    evidence=tuple(dict.fromkeys(evidence)),
                    explanation=f"Matched phrase(s): {', '.join(dict.fromkeys(evidence))}.",
                    recommendation=recommendation,
                )
            )

    if suspicious_links:
        indicators.append(
            MessageIndicator(
                category="Suspicious link",
                points=25,
                evidence=suspicious_links,
                explanation=(
                    "These link(s) use HTTP, an IP address, a URL shortener, or contain "
                    "credential-related terms. Link destinations were not opened."
                ),
                recommendation=(
                    "Do not open suspicious links. Check the destination through a trusted "
                    "official website or app instead."
                ),
            )
        )

    score = min(sum(indicator.points for indicator in indicators), 100)
    if score <= 30:
        level = "LOW"
    elif score <= 60:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return MessageAssessment(
        score=score,
        level=level,
        indicators=tuple(indicators),
        links_found=links,
        suspicious_links=suspicious_links,
    )