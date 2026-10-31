def validate_text(
	value: object,
	field_name: str,
	max_length: int,
	*,
	allow_empty: bool = False,
	empty_message: str | None = None,
) -> str:
	if not isinstance(value, str):
		raise ValueError(f"{field_name} must be text.")

	normalized = value.strip()
	if not normalized and not allow_empty:
		raise ValueError(empty_message or f"{field_name} is required.")
	if len(normalized) > max_length:
		raise ValueError(f"{field_name} must be {max_length:,} characters or fewer.")
	if any(ord(character) < 32 and character not in "\r\n\t" for character in normalized):
		raise ValueError(f"{field_name} contains unsupported control characters.")
	return normalized
