"""PDF export for security reports.

Converts the Markdown report to a styled PDF using weasyprint.
Falls back gracefully if weasyprint is not installed.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from src.infra.decorators import logged, timed
from src.infra.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# CSS stylesheet for professional PDF rendering
# ---------------------------------------------------------------------------

_PDF_CSS = """\
@page {
    size: A4;
    margin: 2cm 1.8cm 2.5cm 1.8cm;

    @top-center {
        content: "RedSimulator — Security Assessment Report";
        font-family: sans-serif;
        font-size: 8pt;
        color: #555;
    }

    @bottom-center {
        content: "Page " counter(page) " / " counter(pages);
        font-family: sans-serif;
        font-size: 8pt;
        color: #555;
    }
}

/* Force page breaks before major sections */
h1, h2 {
    page-break-before: always;
}

/* No page break before the very first heading */
body > h1:first-child,
body > h2:first-child {
    page-break-before: avoid;
}

/* Avoid orphaned headings at the bottom of a page */
h1, h2, h3, h4 {
    page-break-after: avoid;
}

body {
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 10pt;
    line-height: 1.5;
    color: #1a1a1a;
}

/* Dark header band */
h1 {
    background-color: #1a1a2e;
    color: #ffffff;
    padding: 14px 20px;
    border-radius: 4px;
    font-size: 18pt;
    margin-top: 0;
}

h2 {
    color: #1a1a2e;
    border-bottom: 2px solid #1a1a2e;
    padding-bottom: 4px;
    font-size: 14pt;
}

h3 {
    color: #16213e;
    font-size: 11pt;
}

/* Tables */
table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0;
    font-size: 9pt;
}

th {
    background-color: #1a1a2e;
    color: #ffffff;
    padding: 8px 10px;
    text-align: left;
    font-weight: 600;
}

td {
    padding: 6px 10px;
    border-bottom: 1px solid #ddd;
}

tr:nth-child(even) td {
    background-color: #f5f5f8;
}

tr:nth-child(odd) td {
    background-color: #ffffff;
}

/* Code blocks */
pre {
    background-color: #f0f0f4;
    border: 1px solid #d0d0d8;
    border-radius: 4px;
    padding: 10px 14px;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 8.5pt;
    line-height: 1.4;
    overflow-x: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
}

code {
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 8.5pt;
    background-color: #eef0f5;
    padding: 1px 4px;
    border-radius: 3px;
}

pre code {
    background-color: transparent;
    padding: 0;
}

/* Severity badges */
.severity-critical {
    background-color: #dc2626;
    color: #fff;
    padding: 2px 8px;
    border-radius: 3px;
    font-weight: 700;
    font-size: 8.5pt;
}

.severity-high {
    background-color: #ea580c;
    color: #fff;
    padding: 2px 8px;
    border-radius: 3px;
    font-weight: 700;
    font-size: 8.5pt;
}

.severity-medium {
    background-color: #ca8a04;
    color: #fff;
    padding: 2px 8px;
    border-radius: 3px;
    font-weight: 700;
    font-size: 8.5pt;
}

.severity-low {
    background-color: #2563eb;
    color: #fff;
    padding: 2px 8px;
    border-radius: 3px;
    font-weight: 700;
    font-size: 8.5pt;
}

/* Horizontal rules */
hr {
    border: none;
    border-top: 1px solid #ccc;
    margin: 20px 0;
}

/* Lists */
ul, ol {
    margin: 6px 0 6px 20px;
    padding: 0;
}

li {
    margin-bottom: 3px;
}

/* Strong / bold */
strong {
    color: #1a1a2e;
}

/* Paragraphs */
p {
    margin: 6px 0;
}

/* Report metadata block */
.report-meta {
    background-color: #f8f9fc;
    border-left: 4px solid #1a1a2e;
    padding: 10px 16px;
    margin: 12px 0;
    font-size: 9.5pt;
}
"""

# ---------------------------------------------------------------------------
# Fallback: simple regex-based Markdown to HTML converter
# ---------------------------------------------------------------------------


def _md_to_html_fallback(md: str) -> str:
    """Convert Markdown to HTML using simple regex patterns.

    This is a best-effort fallback used when the ``markdown`` library is
    not installed.  It handles the most common constructs found in the
    RedSimulator reports.
    """
    html_lines: list[str] = []
    lines = md.split("\n")
    in_code_block = False
    in_table = False
    in_list = False

    i = 0
    while i < len(lines):
        line = lines[i]

        # --- Fenced code blocks ---
        if line.strip().startswith("```"):
            if in_code_block:
                html_lines.append("</code></pre>")
                in_code_block = False
            else:
                html_lines.append("<pre><code>")
                in_code_block = True
            i += 1
            continue

        if in_code_block:
            # Escape HTML inside code blocks
            escaped = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            html_lines.append(escaped)
            i += 1
            continue

        stripped = line.strip()

        # --- Horizontal rules ---
        if stripped == "---" or stripped == "***" or stripped == "___":
            if in_table:
                html_lines.append("</tbody></table>")
                in_table = False
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append("<hr>")
            i += 1
            continue

        # --- Headings ---
        heading_match = re.match(r"^(#{1,6})\s+(.+)$", stripped)
        if heading_match:
            if in_table:
                html_lines.append("</tbody></table>")
                in_table = False
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            level = len(heading_match.group(1))
            text = _inline_formatting(heading_match.group(2))
            html_lines.append(f"<h{level}>{text}</h{level}>")
            i += 1
            continue

        # --- Tables ---
        if "|" in stripped and stripped.startswith("|"):
            if in_list:
                html_lines.append("</ul>")
                in_list = False

            # Check if this is a separator row (|---|---|)
            if re.match(r"^\|[\s\-:|]+\|$", stripped):
                i += 1
                continue

            cells = [c.strip() for c in stripped.split("|")[1:-1]]

            if not in_table:
                html_lines.append("<table><thead><tr>")
                for cell in cells:
                    html_lines.append(f"<th>{_inline_formatting(cell)}</th>")
                html_lines.append("</tr></thead><tbody>")
                in_table = True
            else:
                html_lines.append("<tr>")
                for cell in cells:
                    formatted = _apply_severity_badge(cell)
                    html_lines.append(f"<td>{formatted}</td>")
                html_lines.append("</tr>")
            i += 1
            continue

        # Close table if we are no longer in a table row
        if in_table and not stripped.startswith("|"):
            html_lines.append("</tbody></table>")
            in_table = False

        # --- Unordered lists ---
        list_match = re.match(r"^[-*]\s+(.+)$", stripped)
        if list_match:
            if not in_list:
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li>{_inline_formatting(list_match.group(1))}</li>")
            i += 1
            continue

        # Close list if no longer in a list item
        if in_list and not stripped.startswith("-") and not stripped.startswith("*"):
            html_lines.append("</ul>")
            in_list = False

        # --- Empty lines ---
        if not stripped:
            i += 1
            continue

        # --- Paragraphs ---
        html_lines.append(f"<p>{_inline_formatting(stripped)}</p>")
        i += 1

    # Close any open blocks
    if in_code_block:
        html_lines.append("</code></pre>")
    if in_table:
        html_lines.append("</tbody></table>")
    if in_list:
        html_lines.append("</ul>")

    return "\n".join(html_lines)


def _inline_formatting(text: str) -> str:
    """Apply inline Markdown formatting (bold, code, links)."""
    # Bold + italic
    text = re.sub(r"\*\*\*(.+?)\*\*\*", r"<strong><em>\1</em></strong>", text)
    # Bold
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    # Italic
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    # Inline code
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    # Links
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    # Apply severity badges
    text = _apply_severity_badge(text)
    return text


def _apply_severity_badge(text: str) -> str:
    """Wrap standalone severity keywords in styled spans."""
    for sev, css_class in (
        ("CRITICAL", "severity-critical"),
        ("HIGH", "severity-high"),
        ("MEDIUM", "severity-medium"),
        ("LOW", "severity-low"),
    ):
        # Only match standalone severity words (not inside other words)
        text = re.sub(
            rf"\b({sev})\b",
            rf'<span class="{css_class}">\1</span>',
            text,
        )
    return text


# ---------------------------------------------------------------------------
# Markdown to HTML (with library or fallback)
# ---------------------------------------------------------------------------


def _md_to_html(md: str) -> str:
    """Convert Markdown to HTML, using the ``markdown`` library if available."""
    try:
        import markdown as md_lib

        html_body = md_lib.markdown(
            md,
            extensions=["tables", "fenced_code", "toc"],
            output_format="html",
        )
        logger.debug("Markdown converted to HTML via 'markdown' library")
    except ImportError:
        logger.info("Package 'markdown' not installed, using built-in fallback converter")
        html_body = _md_to_html_fallback(md)

    # Post-process: apply severity badges to the HTML produced by either path
    html_body = _apply_severity_badge(html_body)

    return html_body


# ---------------------------------------------------------------------------
# Full HTML document assembly
# ---------------------------------------------------------------------------


def _wrap_html(body_html: str) -> str:
    """Wrap an HTML body fragment in a full HTML document with CSS."""
    now = datetime.now(ZoneInfo("America/Toronto")).strftime("%Y-%m-%d %H:%M")
    return f"""\
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>RedSimulator — Security Assessment Report</title>
<style>
{_PDF_CSS}
</style>
</head>
<body>
<div class="report-meta">
    <strong>RedSimulator — Security Assessment Report</strong><br>
    Generated: {now} (America/Toronto)
</div>
{body_html}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@logged
@timed
def export_pdf(report_markdown: str, output_path: str | Path) -> Path | None:
    """Export a Markdown report to PDF.

    Converts the Markdown report to styled HTML, then renders it as a
    professional PDF using *weasyprint*.  If weasyprint is not installed
    the function logs a warning and returns ``None`` without raising.

    Args:
        report_markdown: The report in Markdown format.
        output_path: Where to save the PDF.

    Returns:
        Path to the generated PDF, or None if export failed.
    """
    output_path = Path(output_path)

    # Step 1: Markdown -> HTML
    body_html = _md_to_html(report_markdown)
    full_html = _wrap_html(body_html)

    # Step 2: HTML -> PDF via weasyprint
    try:
        from weasyprint import HTML  # type: ignore[import-untyped]
    except ImportError:
        logger.warning(
            "weasyprint is not installed — PDF export skipped. "
            "Install it with: pip install 'redsimulator[pdf]'"
        )
        return None

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        HTML(string=full_html).write_pdf(str(output_path))
        logger.info("PDF report written to %s", output_path)
        return output_path
    except Exception:
        logger.exception("Failed to generate PDF")
        return None
