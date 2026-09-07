"""
Input validation, adversarial injection detection, and content sanitization.
"""
from __future__ import annotations

import html
import re
from typing import Optional
from app.core.logging import get_logger

logger = get_logger("security_validation")

# Cypher injection signatures
CYPHER_INJECTION_PATTERNS = [
    r"(?i)\bUNION\b.*\bMATCH\b",
    r"(?i)\bLOAD\s+CSV\b",
    r"(?i)\bDROP\s+CONSTRAINT\b",
    r"(?i)\bDROP\s+INDEX\b",
    r"(?i)\bCALL\s+dbms\b",
    r"(?i)\bCALL\s+apoc\b",
    r"(?i)\bDETACH\s+DELETE\b",
    r"(?i)'.*OR.*'.*=",
    r'(?i)".*OR.*".*=',
    r"(?i);\s*DROP\b",
]

# SQL injection signatures
SQL_INJECTION_PATTERNS = [
    r"(?i)\bUNION\s+ALL\s+SELECT\b",
    r"(?i)\bOR\s+1=1\b",
    r"(?i)'.*OR.*'1'='1",
    r"(?i);\s*DROP\s+TABLE\b",
]

# Prompt injection signatures
PROMPT_INJECTION_PATTERNS = [
    r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?",
    r"(?i)disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions?",
    r"(?i)you\s+are\s+now\s+(?:a|an)\b",
    r"(?i)jailbreak",
    r"(?i)DAN\s+mode",
    r"(?i)show\s+(?:me\s+)?(?:your\s+)?system\s+prompt",
    r"(?i)repeat\s+(?:the\s+words\s+above|everything\s+above)",
    r"(?i)reveal\s+(?:your\s+)?internal\s+instructions?",
]

# XSS signatures
XSS_PATTERNS = [
    r"(?i)<script.*?>.*?</script.*?>",
    r"(?i)javascript:",
    r"(?i)onload\s*=",
    r"(?i)onerror\s*=",
    r"(?i)<iframe.*?>",
    r"(?i)<img.*?onerror.*?>",
]


class ValidationResult:
    """Result of input validation."""

    def __init__(self, is_valid: bool, error: Optional[str] = None, threat_type: Optional[str] = None) -> None:
        self.is_valid = is_valid
        self.error = error
        self.threat_type = threat_type


def validate_query_input(query: str, max_length: int = 1000) -> ValidationResult:
    """Validate user query against size limits and adversarial injection patterns."""
    if not query or len(query.strip()) < 3:
        return ValidationResult(False, "Query must be at least 3 characters", "length_too_short")

    if len(query) > max_length:
        return ValidationResult(False, f"Query exceeds maximum length of {max_length} characters", "length_too_long")

    # Path traversal check
    if "../" in query or "..\\" in query:
        logger.warning("path_traversal_attempt_detected", query=query)
        return ValidationResult(False, "Query contains potentially malicious content", "path_traversal")

    # XSS Check
    for pat in XSS_PATTERNS:
        if re.search(pat, query, flags=re.DOTALL):
            logger.warning("xss_attempt_detected", query=query)
            return ValidationResult(False, "Query contains potentially malicious content", "xss")

    # Cypher Check
    for pat in CYPHER_INJECTION_PATTERNS:
        if re.search(pat, query):
            logger.warning("cypher_injection_detected", query=query)
            return ValidationResult(False, "Query contains potentially malicious content", "cypher_injection")

    # SQL Check
    for pat in SQL_INJECTION_PATTERNS:
        if re.search(pat, query):
            logger.warning("sql_injection_detected", query=query)
            return ValidationResult(False, "Query contains potentially malicious content", "sql_injection")

    # Prompt Injection Check
    for pat in PROMPT_INJECTION_PATTERNS:
        if re.search(pat, query):
            logger.warning("prompt_injection_detected", query=query)
            return ValidationResult(False, "Query contains potentially malicious content", "prompt_injection")

    return ValidationResult(True)


def validate_entity_id(entity_id: str) -> bool:
    """Validate an entity identifier format."""
    if not entity_id or len(entity_id) > 100:
        return False
    return bool(re.match(r"^[a-zA-Z0-9][\w\.\-]{0,99}$", entity_id))


def sanitize_for_display(text: str) -> str:
    """Sanitize text for safe HTML display - escape HTML entities."""
    if not text:
        return ""
    return html.escape(text)


def sanitize_graph_content(text: str) -> str:
    """Sanitize text retrieved from graph before placing into LLM prompt."""
    if not text:
        return ""
    cleaned = re.sub(r"[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]", "", text)
    # Filter prompt injection phrases in graph text
    for pat in PROMPT_INJECTION_PATTERNS:
        cleaned = re.sub(pat, "[FILTERED]", cleaned)
    return cleaned.strip()
