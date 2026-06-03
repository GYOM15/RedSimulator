"""Main orchestrator for passive scanning.

PassiveAnalyzer runs all registered passive checks against HTTP responses.
It can analyze individual responses or iterate over all endpoints in a
ScanResult, fetching each one and running the full check suite.
"""

import requests

from src.infra.config import settings
from src.infra.decorators import logged, timed
from src.infra.logging import get_logger
from src.models.scan_result import ScanResult
from src.passive.checks import get_all_checks
from src.passive.models import PassiveFinding, PassiveReport

logger = get_logger(__name__)


def _parse_cookies_from_response(resp: requests.Response) -> list[dict]:
    """Parse Set-Cookie headers into structured dicts.

    Extracts cookie name, flags (Secure, HttpOnly, SameSite), and the
    raw header string for evidence reporting.
    """
    cookies: list[dict] = []

    # Access raw Set-Cookie headers
    raw_headers: list[str] = []
    if hasattr(resp.raw, "headers") and hasattr(resp.raw.headers, "getlist"):
        raw_headers = resp.raw.headers.getlist("Set-Cookie")
    elif "Set-Cookie" in resp.headers:
        raw_headers = [resp.headers["Set-Cookie"]]

    for raw in raw_headers:
        if not raw:
            continue
        parts = raw.split(";")
        name_value = parts[0].strip()
        name = name_value.split("=")[0].strip() if "=" in name_value else name_value

        lower = raw.lower()
        samesite_value = ""
        for part in parts[1:]:
            stripped = part.strip().lower()
            if stripped.startswith("samesite="):
                samesite_value = stripped.split("=", 1)[1].strip()

        cookies.append(
            {
                "name": name,
                "raw": raw,
                "secure": "secure" in lower,
                "httponly": "httponly" in lower,
                "samesite": samesite_value,
            }
        )

    return cookies


class PassiveAnalyzer:
    """Runs all passive checks against HTTP responses.

    Usage::

        analyzer = PassiveAnalyzer()

        # Analyze a single response
        findings = analyzer.analyze_response(url, 200, headers, body, cookies)

        # Analyze all endpoints from a scan
        report = analyzer.analyze_scan_result(scan_result)
    """

    def __init__(self) -> None:
        self.checks = get_all_checks()
        self.report = PassiveReport()
        logger.info("PassiveAnalyzer initialized with %d checks", len(self.checks))

    @logged
    def analyze_response(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
        cookies: list[dict] | None = None,
    ) -> list[PassiveFinding]:
        """Run all checks against a single response.

        Args:
            url: The URL that was requested.
            status_code: HTTP response status code.
            headers: Response headers as a dict.
            body: Response body as text.
            cookies: Parsed cookie dicts (optional).

        Returns:
            List of findings from all checks for this response.
        """
        response_findings: list[PassiveFinding] = []

        for check in self.checks:
            try:
                check_findings = check.check(url, status_code, headers, body, cookies)
                response_findings.extend(check_findings)
            except Exception:
                logger.exception("Check '%s' failed on %s", check.name, url)

        self.report.findings.extend(response_findings)
        logger.debug(
            "%d finding(s) for %s (total: %d)",
            len(response_findings),
            url,
            len(self.report.findings),
        )
        return response_findings

    @logged
    @timed
    def analyze_scan_result(self, scan: ScanResult) -> PassiveReport:
        """Run passive checks against all endpoints in a scan result.

        For each endpoint with a 200 status, makes a GET request and
        analyzes the response headers, body, and cookies.

        Args:
            scan: The ScanResult from the scanner phase.

        Returns:
            A PassiveReport with accumulated findings.
        """
        base_url = scan.target.rstrip("/")
        analyzed = 0

        for ep in scan.endpoints:
            url = f"{base_url}{ep.path}"
            try:
                resp = requests.get(
                    url,
                    timeout=settings.request_timeout,
                    allow_redirects=False,
                )
            except requests.RequestException as e:
                logger.warning("Failed to fetch %s: %s", url, e)
                continue

            cookies = _parse_cookies_from_response(resp)

            self.analyze_response(
                url=url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                cookies=cookies,
            )
            analyzed += 1

        logger.info(
            "Passive scan complete: %d endpoints analyzed, %d finding(s)",
            analyzed,
            len(self.report.findings),
        )
        return self.report

    def get_report(self) -> PassiveReport:
        """Return accumulated findings."""
        return self.report


def analyze_response(
    url: str,
    status_code: int,
    headers: dict,
    body: str,
    cookies: list[dict] | None = None,
) -> list[PassiveFinding]:
    """Convenience function: run all passive checks on a single response.

    Creates a one-shot PassiveAnalyzer and returns the findings.
    """
    analyzer = PassiveAnalyzer()
    return analyzer.analyze_response(url, status_code, headers, body, cookies)
