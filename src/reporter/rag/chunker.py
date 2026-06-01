"""Smart semantic chunking for security reports.

Implements recursive hierarchical chunking that splits Markdown reports
by heading levels (H1 -> H2 -> H3 -> paragraphs -> sentences) and enriches
each chunk with metadata about severity, attack types, vulnerability IDs,
and endpoint paths.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.infra.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class Chunk:
    """A text chunk with rich metadata extracted from the content.

    Attributes:
        text:     The raw text content of the chunk.
        metadata: Structured metadata including:
                  - section_path: hierarchical heading path (e.g. "Executive Summary > SQL Injection")
                  - chunk_type:   one of "heading", "paragraph", "table", "list"
                  - severity:     detected severity level or None
                  - attack_types: list of detected attack type keywords
                  - vuln_ids:     list of vulnerability IDs (VEC-001, etc.)
                  - endpoints:    list of endpoint paths (/rest/user/login, etc.)
                  - index:        positional index within the full chunk list
    """

    text: str
    metadata: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Metadata extraction helpers
# ---------------------------------------------------------------------------

_SEVERITY_PATTERN = re.compile(
    r"\b(CRITICAL|HIGH|MEDIUM|LOW)\b",
    re.IGNORECASE,
)

_ATTACK_TYPE_KEYWORDS: dict[str, re.Pattern] = {
    "sqli": re.compile(r"\b(sqli|sql[\s_-]?injection)\b", re.IGNORECASE),
    "xss": re.compile(r"\b(xss|cross[\s_-]?site[\s_-]?scripting)\b", re.IGNORECASE),
    "idor": re.compile(r"\b(idor|insecure[\s_-]?direct[\s_-]?object)\b", re.IGNORECASE),
    "csrf": re.compile(r"\b(csrf|cross[\s_-]?site[\s_-]?request[\s_-]?forgery)\b", re.IGNORECASE),
    "traversal": re.compile(
        r"\b(path[\s_-]?traversal|directory[\s_-]?traversal|lfi|rfi)\b", re.IGNORECASE
    ),
    "redirect": re.compile(r"\b(open[\s_-]?redirect|url[\s_-]?redirect)\b", re.IGNORECASE),
    "auth_bypass": re.compile(
        r"\b(auth[\s_-]?bypass|authentication[\s_-]?bypass|broken[\s_-]?auth)\b", re.IGNORECASE
    ),
    "command_injection": re.compile(
        r"\b(command[\s_-]?injection|os[\s_-]?injection|rce)\b", re.IGNORECASE
    ),
    "info_disclosure": re.compile(
        r"\b(info(?:rmation)?[\s_-]?disclosure|sensitive[\s_-]?data[\s_-]?exposure)\b",
        re.IGNORECASE,
    ),
    "ssrf": re.compile(r"\b(ssrf|server[\s_-]?side[\s_-]?request[\s_-]?forgery)\b", re.IGNORECASE),
    "xxe": re.compile(r"\b(xxe|xml[\s_-]?external[\s_-]?entity)\b", re.IGNORECASE),
}

_VULN_ID_PATTERN = re.compile(r"\b(VEC-\d{3,})\b")

_ENDPOINT_PATTERN = re.compile(
    r"(/(?:rest|api|ftp|admin|b2b|metrics|security|socket|video)[\w/.-]*)"
)


def _extract_metadata(text: str, section_path: str = "", chunk_type: str = "paragraph") -> dict:
    """Extract structured metadata from a chunk's text content.

    Returns a dict suitable for use as ``Chunk.metadata``.
    """
    # Severity: pick the highest mentioned
    severities_found = _SEVERITY_PATTERN.findall(text)
    severity = severities_found[0].upper() if severities_found else None

    # Attack types
    attack_types: list[str] = []
    for attack_name, pattern in _ATTACK_TYPE_KEYWORDS.items():
        if pattern.search(text):
            attack_types.append(attack_name)

    # Vulnerability IDs
    vuln_ids = _VULN_ID_PATTERN.findall(text)

    # Endpoints
    endpoints = list(set(_ENDPOINT_PATTERN.findall(text)))

    return {
        "section_path": section_path,
        "chunk_type": chunk_type,
        "severity": severity,
        "attack_types": attack_types,
        "vuln_ids": vuln_ids,
        "endpoints": endpoints,
        "index": 0,  # Will be set by smart_chunk
    }


def _detect_chunk_type(text: str) -> str:
    """Detect the dominant content type within a text block."""
    stripped = text.strip()

    # Table detection: lines with pipes
    table_lines = [ln for ln in stripped.splitlines() if "|" in ln]
    if len(table_lines) >= 2:
        return "table"

    # List detection: majority of non-empty lines start with - or *
    non_empty_lines = [ln for ln in stripped.splitlines() if ln.strip()]
    if non_empty_lines:
        list_lines = [
            ln
            for ln in non_empty_lines
            if re.match(r"^\s*[-*+]\s", ln) or re.match(r"^\s*\d+\.\s", ln)
        ]
        if len(list_lines) >= len(non_empty_lines) * 0.5 and len(list_lines) >= 2:
            return "list"

    # Heading detection: starts with #
    if re.match(r"^#{1,6}\s", stripped):
        return "heading"

    return "paragraph"


# ---------------------------------------------------------------------------
# Hierarchical splitting
# ---------------------------------------------------------------------------

_H1_PATTERN = re.compile(r"^(#\s+.+)$", re.MULTILINE)
_H2_PATTERN = re.compile(r"^(##\s+.+)$", re.MULTILINE)
_H3_PATTERN = re.compile(r"^(###\s+.+)$", re.MULTILINE)


def _split_by_heading(text: str, pattern: re.Pattern) -> list[tuple[str, str]]:
    """Split text by a heading pattern, returning (heading_title, body) pairs.

    The first element may have an empty heading_title if there is content
    before the first heading match.
    """
    positions = [(m.start(), m.group(1)) for m in pattern.finditer(text)]

    if not positions:
        return [("", text)]

    sections: list[tuple[str, str]] = []

    # Content before the first heading
    if positions[0][0] > 0:
        preamble = text[: positions[0][0]].strip()
        if preamble:
            sections.append(("", preamble))

    for idx, (pos, heading) in enumerate(positions):
        end = positions[idx + 1][0] if idx + 1 < len(positions) else len(text)
        body = text[pos:end].strip()
        # Extract just the heading text (without the # prefix)
        heading_text = re.sub(r"^#{1,6}\s+", "", heading).strip()
        sections.append((heading_text, body))

    return sections


def _split_paragraphs(text: str) -> list[str]:
    """Split text at paragraph boundaries (double newlines)."""
    paragraphs = re.split(r"\n\s*\n", text)
    return [p.strip() for p in paragraphs if p.strip()]


def _split_sentences(text: str, max_size: int, overlap_sentences: int = 2) -> list[str]:
    """Split text at sentence boundaries with overlap, respecting max_size.

    Each chunk overlaps with the next by *overlap_sentences* sentences for
    continuity.
    """
    raw_sentences = re.split(r"(?<=[.!?:;])\s+", text)
    sentences = [s.strip() for s in raw_sentences if s.strip()]

    if not sentences:
        return [text] if text.strip() else []

    chunks: list[str] = []
    start_idx = 0

    while start_idx < len(sentences):
        current_chunk: list[str] = []
        current_len = 0

        idx = start_idx
        while idx < len(sentences):
            sent = sentences[idx]
            addition = len(sent) + (1 if current_chunk else 0)
            if current_chunk and current_len + addition > max_size:
                break
            current_chunk.append(sent)
            current_len += addition
            idx += 1

        if current_chunk:
            chunks.append(" ".join(current_chunk))

        consumed = idx - start_idx
        advance = max(consumed - overlap_sentences, 1)
        start_idx += advance

    return chunks


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def smart_chunk(text: str, max_chunk_size: int = 500) -> list[Chunk]:
    """Recursively chunk markdown text with metadata extraction.

    Strategy (recursive hierarchical chunking):
        1. Split by H1 headings (``# ...``) first.
        2. Within each H1, split by H2 headings (``## ...``).
        3. Within each H2, split by H3 headings (``### ...``).
        4. For sections still too large, split at paragraph boundaries (double newline).
        5. For paragraphs still too large, split at sentence boundaries.
        6. Each chunk carries rich metadata: section_path, chunk_type, severity,
           attack_types, vuln_ids, endpoints, and positional index.

    Args:
        text:           Markdown text to chunk (typically a full security report).
        max_chunk_size: Maximum character length for each chunk.

    Returns:
        Ordered list of Chunk objects with metadata.
    """
    if not text or not text.strip():
        logger.warning("Empty text provided to smart_chunk")
        return []

    chunks: list[Chunk] = []

    def _recursive_split(block: str, section_path: str, depth: int) -> None:
        """Recursively split a block by heading level, then by paragraphs/sentences."""
        # Choose the heading pattern based on current depth
        patterns = [_H1_PATTERN, _H2_PATTERN, _H3_PATTERN]

        if depth < len(patterns):
            sections = _split_by_heading(block, patterns[depth])

            # If splitting produced more than one section, recurse into each
            if len(sections) > 1 or (len(sections) == 1 and sections[0][0]):
                for heading_text, body in sections:
                    path = (
                        f"{section_path} > {heading_text}".strip(" >")
                        if heading_text
                        else section_path
                    )
                    _recursive_split(body, path, depth + 1)
                return

        # No further heading splits possible — split by size if needed
        if len(block) <= max_chunk_size:
            chunk_type = _detect_chunk_type(block)
            metadata = _extract_metadata(block, section_path, chunk_type)
            chunks.append(Chunk(text=block, metadata=metadata))
            return

        # Split at paragraph boundaries
        paragraphs = _split_paragraphs(block)

        if len(paragraphs) > 1:
            for para in paragraphs:
                if len(para) <= max_chunk_size:
                    chunk_type = _detect_chunk_type(para)
                    metadata = _extract_metadata(para, section_path, chunk_type)
                    chunks.append(Chunk(text=para, metadata=metadata))
                else:
                    # Split oversized paragraph at sentence boundaries
                    sentence_chunks = _split_sentences(para, max_chunk_size)
                    for sc in sentence_chunks:
                        chunk_type = _detect_chunk_type(sc)
                        metadata = _extract_metadata(sc, section_path, chunk_type)
                        chunks.append(Chunk(text=sc, metadata=metadata))
        else:
            # Single block too large — split at sentence boundaries
            sentence_chunks = _split_sentences(block, max_chunk_size)
            for sc in sentence_chunks:
                chunk_type = _detect_chunk_type(sc)
                metadata = _extract_metadata(sc, section_path, chunk_type)
                chunks.append(Chunk(text=sc, metadata=metadata))

    _recursive_split(text, "", 0)

    # Assign positional indices
    for idx, chunk in enumerate(chunks):
        chunk.metadata["index"] = idx

    logger.info("smart_chunk produced %d chunks from %d characters", len(chunks), len(text))
    return chunks
