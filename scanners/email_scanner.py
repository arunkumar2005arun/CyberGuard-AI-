import ipaddress
import re
from dataclasses import dataclass

from scanners.message_scanner import MessageIndicator, analyze_message


_EMAIL_PATTERN = re.compile(r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Z0-9.-]+)$", re.IGNORECASE)
_BRAND_DOMAINS = {
    "amazon": ("amazon.com",),
    "apple": ("apple.com",),
    "google": ("google.com", "googlemail.com"),
    "microsoft": ("microsoft.com", "live.com", "outlook.com"),
    "netflix": ("netflix.com",),
    "paypal": ("paypal.com",),
}
_BRAND_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(brand) for brand in _BRAND_DOMAINS) + r")\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class EmailAssessment:
    sender: str
    subject: str
    score: int
    level: str
    indicators: tuple[MessageIndicator, ...]
    links_found: tuple[str, ...]
    suspicious_links: tuple[str, ...]

    @property
    def recommendations(self) -> tuple[str, ...]:
        if not self.indicators:
            return (
                "No configured warning signs were detected. Verify unexpected requests "
                "independently before replying or opening links.",
            )
        return tuple(dict.fromkeys(item.recommendation for item in self.indicators))


def _parse_sender(sender: str) -> tuple[str, str]:
    normalized_sender = sender.strip()
    match = _EMAIL_PATTERN.fullmatch(normalized_sender)
    if not match:
        raise ValueError("Enter a valid sender email address, such as name@example.com.")

    domain = match.group(1).lower().rstrip(".")
    labels = domain.split(".")
    if (
        len(domain) > 253
        or len(labels) < 2
        or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels)
    ):
        raise ValueError("Enter a sender address with a valid domain.")
    try:
        ipaddress.ip_address(domain.strip("[]"))
    except ValueError:
        pass
    else:
        raise ValueError("A sender address must use a domain name, not an IP address.")
    return normalized_sender, domain


def _sender_indicators(sender: str, domain: str, content: str) -> list[MessageIndicator]:
    local_part = sender.rsplit("@", maxsplit=1)[0].lower()
    findings: list[MessageIndicator] = []

    if domain.startswith("xn--") or ".xn--" in domain:
        findings.append(
            MessageIndicator(
                category="Internationalized sender domain",
                points=25,
                evidence=(domain,),
                explanation=(
                    "The sender domain contains a punycode label that can make look-alike "
                    "characters difficult to distinguish."
                ),
                recommendation=(
                    "Check the sender domain carefully and compare it with the organization's "
                    "known official address."
                ),
            )
        )

    if sum(character.isdigit() for character in local_part) >= 4 or (
        local_part.count("-") >= 2 or local_part.count(".") >= 4
    ):
        findings.append(
            MessageIndicator(
                category="Unusual sender address pattern",
                points=10,
                evidence=(sender,),
                explanation=(
                    "The sender's local address has multiple digits or separators, which can "
                    "be used in throwaway or look-alike addresses."
                ),
                recommendation=(
                    "Confirm the sender address against a trusted contact or the organization's "
                    "official contact information."
                ),
            )
        )

    seen_brands: set[str] = set()
    for match in _BRAND_PATTERN.finditer(content):
        brand = match.group(1).lower()
        if brand in seen_brands:
            continue
        seen_brands.add(brand)
        allowed_domains = _BRAND_DOMAINS[brand]
        if not any(domain == allowed or domain.endswith(f".{allowed}") for allowed in allowed_domains):
            findings.append(
                MessageIndicator(
                    category="Sender and brand domain mismatch",
                    points=30,
                    evidence=(f"{brand} mentioned; sender domain is {domain}",),
                    explanation=(
                        f"The message mentions {brand.title()}, but the sender domain is not "
                        f"one of its configured domains ({', '.join(allowed_domains)})."
                    ),
                    recommendation=(
                        f"Do not use the message link to sign in to {brand.title()}. Open its "
                        "official app or type its known address yourself."
                    ),
                )
            )
    return findings


def analyze_email(sender: str, subject: str, body: str) -> EmailAssessment:
    """Analyze sender and email text locally; discovered links are never visited."""
    normalized_sender, sender_domain = _parse_sender(sender)
    normalized_subject = subject.strip()
    normalized_body = body.strip()
    if not normalized_subject and not normalized_body:
        raise ValueError("Enter an email subject or body to analyze.")

    content = "\n".join(part for part in (normalized_subject, normalized_body) if part)
    content_assessment = analyze_message(content)
    sender_findings = _sender_indicators(normalized_sender, sender_domain, content)
    indicators = tuple(sender_findings) + content_assessment.indicators
    score = min(sum(indicator.points for indicator in indicators), 100)
    if score <= 30:
        level = "LOW"
    elif score <= 60:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return EmailAssessment(
        sender=normalized_sender,
        subject=normalized_subject,
        score=score,
        level=level,
        indicators=indicators,
        links_found=content_assessment.links_found,
        suspicious_links=content_assessment.suspicious_links,
    )