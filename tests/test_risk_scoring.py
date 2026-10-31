import unittest
from dataclasses import dataclass

from core.risk_scoring import classify_risk_score, score_url_features


@dataclass(frozen=True)
class URLFeatures:
    domain: str = "example.com"
    https_enabled: bool = True
    total_length: int = 24
    uses_ip_address: bool = False
    suspicious_keywords: tuple[str, ...] = ()
    suspicious_domain_patterns: tuple[str, ...] = ()


class URLRiskScoringTests(unittest.TestCase):
    def test_no_indicators_is_low_risk(self) -> None:
        assessment = score_url_features(URLFeatures())

        self.assertEqual((assessment.score, assessment.level), (0, "Low Risk"))
        self.assertEqual(assessment.findings, ())
        self.assertTrue(assessment.recommendations)

    def test_risk_level_boundaries(self) -> None:
        cases = (
            (30, "Low Risk"),
            (31, "Medium Risk"),
            (60, "Medium Risk"),
            (61, "High Risk"),
        )
        for score, expected_level in cases:
            with self.subTest(score=score):
                self.assertEqual(classify_risk_score(score), expected_level)

    def test_classifier_rejects_scores_outside_supported_range(self) -> None:
        for score in (-1, 101):
            with self.subTest(score=score), self.assertRaises(ValueError):
                classify_risk_score(score)

    def test_all_indicators_are_explained_and_score_is_capped(self) -> None:
        features = URLFeatures(
            domain="xn--fake-123.example.very.long.subdomain",
            https_enabled=False,
            total_length=250,
            uses_ip_address=True,
            suspicious_keywords=("login", "verify", "bank", "secure"),
            suspicious_domain_patterns=("punycode", "many_labels", "digits_and_hyphens"),
        )

        assessment = score_url_features(features)
        indicators = {finding.indicator for finding in assessment.findings}

        self.assertEqual((assessment.score, assessment.level), (100, "High Risk"))
        self.assertEqual(
            indicators,
            {
                "HTTP instead of HTTPS",
                "IP address used as host",
                "Suspicious URL keywords",
                "Unusually long URL",
                "Punycode domain label",
                "Many domain labels",
                "Digit- and hyphen-heavy domain label",
            },
        )
        self.assertEqual(len(assessment.recommendations), len(assessment.findings))
        self.assertTrue(all(finding.explanation and finding.recommendation for finding in assessment.findings))

    def test_keyword_points_are_limited_to_three_matches(self) -> None:
        assessment = score_url_features(
            URLFeatures(suspicious_keywords=("login", "verify", "password", "bank"))
        )

        keyword_finding = next(
            finding for finding in assessment.findings if finding.indicator == "Suspicious URL keywords"
        )
        self.assertEqual(keyword_finding.points, 30)

    def test_long_url_thresholds(self) -> None:
        for length, expected_points in ((100, 0), (101, 10), (200, 10), (201, 20)):
            with self.subTest(length=length):
                assessment = score_url_features(URLFeatures(total_length=length))
                points = sum(
                    finding.points
                    for finding in assessment.findings
                    if finding.indicator == "Unusually long URL"
                )
                self.assertEqual(points, expected_points)


if __name__ == "__main__":
    unittest.main()