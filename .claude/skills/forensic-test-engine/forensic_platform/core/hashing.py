import hashlib


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def column_signature(columns: list[tuple[str, str]]) -> str:
    joined = "|".join(f"{name}:{data_type}" for name, data_type in sorted(columns))
    return sha256_text(joined)
