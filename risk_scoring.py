from dataclasses import dataclass
from typing import Protocol


class URLFeatureSet(Protocol):
    domain: str
    https_enabled: bool
    total_length: int
    uses_ip_address: bool
    suspicious_keywords: tuple[str, ...]
    suspicious_domain_patterns: tuple[str, ...]


@dataclass(frozen=True)
class RiskFinding:
    indicator: str
    points: int
    explanation: str
    recommendation: str


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    findings: tuple[RiskFinding, ...]

    @property
    def recommendations(self) -> tuple[str, ...]:
        if not self.findings:
            return (
                "No configured risk indicators were detected. Confirm the address "
                "independently before entering sensitive information.",
            )
        return tuple(finding.recommendation for finding in self.findings)


def classify_risk_score(score: int) -> str:
    if not 0 <= score <= 100:
        raise ValueError("A risk score must be between 0 and 100.")
    if score <= 30:
        return "Low Risk"
    if score <= 60:
        return "Medium Risk"
    return "High Risk"


def score_url_features(features: URLFeatureSet) -> RiskAssessment:
    """Score extracted URL attributes only; no network access is performed."""
    findings: list[RiskFinding] = []

    if not features.https_enabled:
        findings.append(
            RiskFinding(
                indicator="HTTP instead of HTTPS",
                points=20,
                explanation="The URL uses HTTP, so its connection is not protected by HTTPS.",
                recommendation="Avoid entering credentials or payment details unless you can "
                "independently confirm the official HTTPS address.",
            )
        )

    if features.uses_ip_address:
        findings.append(
            RiskFinding(
                indicator="IP address used as host",
                points=30,
                explanation="The host is an IP address rather than a named domain.",
                recommendation="Verify the destination through the organization's official "
                "website or another trusted channel before proceeding.",
            )
        )

    keyword_count = min(len(features.suspicious_keywords), 3)
    if keyword_count:
        keywords = ", ".join(features.suspicious_keywords)
        findings.append(
            RiskFinding(
                indicator="Suspicious URL keywords",
                points=keyword_count * 10,
                explanation=f"Matched keyword(s): {keywords}. These terms can be used in "
                "credential or account-baiting links.",
                recommendation="Do not follow an unexpected link asking you to log in, verify "
                "an account, or update payment details; navigate to the service directly.",
            )
        )

    if features.total_length > 200:
        findings.append(
            RiskFinding(
                indicator="Unusually long URL",
                points=20,
                explanation=f"The URL is {features.total_length} characters long; URLs over "
                "200 characters receive this indicator.",
                recommendation="Treat the link cautiously and confirm the destination domain "
                "before opening it.",
            )
        )
    elif features.total_length > 100:
        findings.append(
            RiskFinding(
                indicator="Unusually long URL",
                points=10,
                explanation=f"The URL is {features.total_length} characters long; URLs over "
                "100 characters receive this indicator.",
                recommendation="Treat the link cautiously and confirm the destination domain "
                "before opening it.",
            )
        )

    for pattern in features.suspicious_domain_patterns:
        if pattern == "punycode":
            findings.append(
                RiskFinding(
                    indicator="Punycode domain label",
                    points=15,
                    explanation="The domain contains an internationalized label encoded with "
                    "the xn-- prefix, which can obscure look-alike characters.",
                    recommendation="Check the domain spelling carefully and use a known "
                    "bookmark or type the organization's address yourself.",
                )
            )
        elif pattern == "many_labels":
            findings.append(
                RiskFinding(
                    indicator="Many domain labels",
                    points=15,
                    explanation="The hostname has five or more dot-separated labels, which can "
                    "make the actual registered destination harder to recognize.",
                    recommendation="Read the hostname from right to left and verify the "
                    "registered domain through a trusted source.",
                )
            )
        elif pattern == "digits_and_hyphens":
            findings.append(
                RiskFinding(
                    indicator="Digit- and hyphen-heavy domain label",
                    points=10,
                    explanation="A domain label combines at least three digits with a hyphen, "
                    "a pattern sometimes used to imitate legitimate domains.",
                    recommendation="Compare the exact spelling with the organization's known "
                    "official domain before trusting the link.",
                )
            )

    score = min(sum(finding.points for finding in findings), 100)
    return RiskAssessment(
        score=score,
        level=classify_risk_score(score),
        findings=tuple(findings),
    )