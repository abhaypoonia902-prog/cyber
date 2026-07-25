from pathlib import Path
from config import Config

def validate_log_extension(filename: str) -> bool:
    return Path(filename).suffix.lower() in Config.ALLOWED_LOG_EXT

def sanitize_text(value: str, max_len: int = 5000) -> str:
    return (value or "").strip()[:max_len]