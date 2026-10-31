import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from core.validation import validate_text

SUSPICIOUS_KEYWORDS = ("login", "verify", "password", "bank", "secure", "update")
MAX_URL_LENGTH = 2048
DOMAIN_LABEL_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


@dataclass(frozen=True)
class URLFeatures:
	domain: str
	https_enabled: bool
	total_length: int
	uses_ip_address: bool
	has_credentials: bool
	suspicious_keywords: tuple[str, ...]
	suspicious_domain_patterns: tuple[str, ...]


def _is_valid_domain(hostname: str) -> bool:
	domain = hostname.rstrip(".")
	if not domain or len(domain) > 253:
		return False

	for label in domain.split("."):
		try:
			ascii_label = label.encode("idna").decode("ascii").lower()
		except UnicodeError:
			return False
		if len(ascii_label) > 63 or not DOMAIN_LABEL_PATTERN.fullmatch(ascii_label):
			return False
	return True


def extract_url_features(value: str) -> URLFeatures:
	"""Extract URL features locally; this function never makes a network request."""
	url = validate_text(
		value,
		"URL",
		MAX_URL_LENGTH,
		empty_message="Enter a URL to analyze.",
	)
	if any(character.isspace() or ord(character) < 32 for character in url):
		raise ValueError("The URL cannot contain spaces or control characters.")

	try:
		parsed_url = urlsplit(url)
		hostname = parsed_url.hostname
		scheme = parsed_url.scheme.lower()
		has_credentials = parsed_url.username is not None or parsed_url.password is not None
		_ = parsed_url.port
	except ValueError as error:
		raise ValueError("Enter a valid URL with a correctly formatted host and port.") from error

	if scheme not in {"http", "https"} or not hostname:
		raise ValueError("Enter a complete URL beginning with http:// or https://.")

	try:
		ipaddress.ip_address(hostname)
		uses_ip_address = True
	except ValueError:
		if not _is_valid_domain(hostname):
			raise ValueError("The URL contains an invalid domain name or IP address.")
		uses_ip_address = False

	lowered_url = url.lower()
	keywords = tuple(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lowered_url)
	domain_labels = hostname.lower().rstrip(".").split(".")
	domain_patterns: list[str] = []
	if any(label.startswith("xn--") for label in domain_labels):
		domain_patterns.append("punycode")
	if len(domain_labels) >= 5:
		domain_patterns.append("many_labels")
	if any(
		label.count("-") >= 1 and sum(character.isdigit() for character in label) >= 3
		for label in domain_labels
	):
		domain_patterns.append("digits_and_hyphens")

	return URLFeatures(
		domain=hostname.lower(),
		https_enabled=scheme == "https",
		total_length=len(url),
		uses_ip_address=uses_ip_address,
		has_credentials=has_credentials,
		suspicious_keywords=keywords,
		suspicious_domain_patterns=tuple(domain_patterns),
	)
