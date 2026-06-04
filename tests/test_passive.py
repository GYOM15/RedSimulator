"""Tests for passive scanning checks.

Verifies passive models, header checks, cookie checks, CORS checks,
and information leakage detection. All tests run without Docker,
mitmproxy, or API keys.
"""

from src.passive.checks.cookies import CookieCheck
from src.passive.checks.cors import CorsCheck
from src.passive.checks.headers import HeaderCheck
from src.passive.checks.information import InformationCheck
from src.passive.models import FindingSeverity, PassiveFinding, PassiveReport

# ---------------------------------------------------------------------------
# TestPassiveModels
# ---------------------------------------------------------------------------


class TestPassiveModels:
    """Test passive scanning data models."""

    def test_finding_severity_enum(self):
        assert FindingSeverity.CRITICAL == "CRITICAL"
        assert FindingSeverity.HIGH == "HIGH"
        assert FindingSeverity.MEDIUM == "MEDIUM"
        assert FindingSeverity.LOW == "LOW"
        assert FindingSeverity.INFO == "INFO"

    def test_passive_finding_creation(self):
        finding = PassiveFinding(
            check_name="test_check",
            severity=FindingSeverity.HIGH,
            title="Test Finding",
            description="A test finding description",
            url="http://test.local",
        )
        assert finding.check_name == "test_check"
        assert finding.severity == FindingSeverity.HIGH
        assert finding.title == "Test Finding"
        assert finding.evidence == ""
        assert finding.cwe_id == ""
        assert finding.remediation == ""

    def test_passive_finding_with_all_fields(self):
        finding = PassiveFinding(
            check_name="test",
            severity=FindingSeverity.CRITICAL,
            title="t",
            description="d",
            url="http://x",
            evidence="evidence here",
            cwe_id="CWE-123",
            remediation="fix it",
        )
        assert finding.evidence == "evidence here"
        assert finding.cwe_id == "CWE-123"
        assert finding.remediation == "fix it"

    def test_passive_report_by_severity(self):
        report = PassiveReport(
            findings=[
                PassiveFinding(
                    check_name="a",
                    severity=FindingSeverity.HIGH,
                    title="t",
                    description="d",
                    url="http://x",
                ),
                PassiveFinding(
                    check_name="b",
                    severity=FindingSeverity.HIGH,
                    title="t",
                    description="d",
                    url="http://x",
                ),
                PassiveFinding(
                    check_name="c",
                    severity=FindingSeverity.LOW,
                    title="t",
                    description="d",
                    url="http://x",
                ),
            ]
        )
        assert report.by_severity["HIGH"] == 2
        assert report.by_severity["LOW"] == 1

    def test_passive_report_by_check(self):
        report = PassiveReport(
            findings=[
                PassiveFinding(
                    check_name="missing_hsts",
                    severity=FindingSeverity.MEDIUM,
                    title="t",
                    description="d",
                    url="http://a",
                ),
                PassiveFinding(
                    check_name="missing_hsts",
                    severity=FindingSeverity.MEDIUM,
                    title="t",
                    description="d",
                    url="http://b",
                ),
                PassiveFinding(
                    check_name="server_leak",
                    severity=FindingSeverity.LOW,
                    title="t",
                    description="d",
                    url="http://a",
                ),
            ]
        )
        assert report.by_check["missing_hsts"] == 2
        assert report.by_check["server_leak"] == 1

    def test_passive_report_empty(self):
        report = PassiveReport()
        assert report.findings == []
        assert report.by_severity == {}
        assert report.by_check == {}


# ---------------------------------------------------------------------------
# TestHeaderCheck
# ---------------------------------------------------------------------------


class TestHeaderCheck:
    """Test the security header passive check."""

    def test_detects_missing_hsts(self):
        check = HeaderCheck()
        findings = check.check(url="http://test.local", status_code=200, headers={}, body="")
        names = [f.check_name for f in findings]
        assert "missing_hsts" in names

    def test_detects_missing_csp(self):
        check = HeaderCheck()
        findings = check.check(url="http://test.local", status_code=200, headers={}, body="")
        names = [f.check_name for f in findings]
        assert "missing_csp" in names

    def test_detects_missing_xcto(self):
        check = HeaderCheck()
        findings = check.check(url="http://test.local", status_code=200, headers={}, body="")
        names = [f.check_name for f in findings]
        assert "missing_xcto" in names

    def test_detects_missing_xfo(self):
        check = HeaderCheck()
        findings = check.check(url="http://test.local", status_code=200, headers={}, body="")
        names = [f.check_name for f in findings]
        assert "missing_xfo" in names

    def test_detects_missing_referrer_policy(self):
        check = HeaderCheck()
        findings = check.check(url="http://test.local", status_code=200, headers={}, body="")
        names = [f.check_name for f in findings]
        assert "missing_referrer_policy" in names

    def test_detects_missing_permissions_policy(self):
        check = HeaderCheck()
        findings = check.check(url="http://test.local", status_code=200, headers={}, body="")
        names = [f.check_name for f in findings]
        assert "missing_permissions_policy" in names

    def test_detects_server_version_leak(self):
        check = HeaderCheck()
        findings = check.check(
            url="http://test.local",
            status_code=200,
            headers={"Server": "Apache/2.4.49"},
            body="",
        )
        assert any(f.check_name == "server_version_leak" for f in findings)

    def test_no_server_leak_without_version(self):
        """A Server header without digits should not trigger the version check."""
        check = HeaderCheck()
        findings = check.check(
            url="http://test.local",
            status_code=200,
            headers={"Server": "nginx"},
            body="",
        )
        assert not any(f.check_name == "server_version_leak" for f in findings)

    def test_detects_x_powered_by(self):
        check = HeaderCheck()
        findings = check.check(
            url="http://test.local",
            status_code=200,
            headers={"X-Powered-By": "Express"},
            body="",
        )
        assert any(f.check_name == "x_powered_by_leak" for f in findings)

    def test_detects_aspnet_version(self):
        check = HeaderCheck()
        findings = check.check(
            url="http://test.local",
            status_code=200,
            headers={"X-AspNet-Version": "4.0.30319"},
            body="",
        )
        assert any(f.check_name == "aspnet_version_leak" for f in findings)

    def test_detects_aspnetmvc_version(self):
        check = HeaderCheck()
        findings = check.check(
            url="http://test.local",
            status_code=200,
            headers={"X-AspNetMvc-Version": "5.2"},
            body="",
        )
        assert any(f.check_name == "aspnetmvc_version_leak" for f in findings)

    def test_no_findings_on_secure_headers(self):
        """All security headers present should produce minimal findings."""
        check = HeaderCheck()
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        }
        findings = check.check(url="http://test.local", status_code=200, headers=headers, body="")
        # No missing-header findings and no leak findings
        assert len(findings) == 0

    def test_check_name_and_description(self):
        check = HeaderCheck()
        assert check.name == "header_check"
        assert check.description != ""


# ---------------------------------------------------------------------------
# TestCookieCheck
# ---------------------------------------------------------------------------


class TestCookieCheck:
    """Test the cookie security passive check."""

    def test_detects_missing_secure(self):
        check = CookieCheck()
        cookies = [
            {
                "name": "session",
                "raw": "session=abc; HttpOnly",
                "secure": False,
                "httponly": True,
                "samesite": "",
            }
        ]
        findings = check.check(
            url="http://test.local", status_code=200, headers={}, body="", cookies=cookies
        )
        assert any(f.check_name == "insecure_cookie" for f in findings)

    def test_detects_missing_httponly(self):
        check = CookieCheck()
        cookies = [
            {
                "name": "token",
                "raw": "token=abc; Secure",
                "secure": True,
                "httponly": False,
                "samesite": "Strict",
            }
        ]
        findings = check.check(
            url="http://test.local", status_code=200, headers={}, body="", cookies=cookies
        )
        assert any(f.check_name == "cookie_no_httponly" for f in findings)

    def test_detects_missing_samesite(self):
        check = CookieCheck()
        cookies = [
            {
                "name": "pref",
                "raw": "pref=x; Secure; HttpOnly",
                "secure": True,
                "httponly": True,
                "samesite": "",
            }
        ]
        findings = check.check(
            url="http://test.local", status_code=200, headers={}, body="", cookies=cookies
        )
        assert any(f.check_name == "cookie_no_samesite" for f in findings)

    def test_session_cookie_httponly_high_severity(self):
        """Missing HttpOnly on session cookies should be HIGH severity."""
        check = CookieCheck()
        cookies = [
            {
                "name": "sessionid",
                "raw": "sessionid=abc",
                "secure": False,
                "httponly": False,
                "samesite": "",
            }
        ]
        findings = check.check(
            url="http://test.local", status_code=200, headers={}, body="", cookies=cookies
        )
        httponly_findings = [f for f in findings if f.check_name == "cookie_no_httponly"]
        assert len(httponly_findings) == 1
        assert httponly_findings[0].severity == FindingSeverity.HIGH

    def test_samesite_none_without_secure(self):
        check = CookieCheck()
        cookies = [
            {
                "name": "track",
                "raw": "track=x; SameSite=None",
                "secure": False,
                "httponly": True,
                "samesite": "none",
            }
        ]
        findings = check.check(
            url="http://test.local", status_code=200, headers={}, body="", cookies=cookies
        )
        assert any(f.check_name == "samesite_none_no_secure" for f in findings)

    def test_secure_prefix_without_flag(self):
        check = CookieCheck()
        cookies = [
            {
                "name": "__Secure-session",
                "raw": "__Secure-session=abc",
                "secure": False,
                "httponly": True,
                "samesite": "Strict",
            }
        ]
        findings = check.check(
            url="http://test.local", status_code=200, headers={}, body="", cookies=cookies
        )
        assert any(f.check_name == "secure_prefix_no_flag" for f in findings)

    def test_no_findings_without_cookies(self):
        check = CookieCheck()
        findings = check.check(
            url="http://test.local", status_code=200, headers={}, body="", cookies=None
        )
        assert findings == []

    def test_no_findings_with_empty_cookies(self):
        check = CookieCheck()
        findings = check.check(
            url="http://test.local", status_code=200, headers={}, body="", cookies=[]
        )
        assert findings == []

    def test_no_findings_on_secure_cookie(self):
        """A cookie with all flags should produce no findings."""
        check = CookieCheck()
        cookies = [
            {
                "name": "safe",
                "raw": "safe=x; Secure; HttpOnly; SameSite=Strict",
                "secure": True,
                "httponly": True,
                "samesite": "strict",
            }
        ]
        findings = check.check(
            url="http://test.local", status_code=200, headers={}, body="", cookies=cookies
        )
        assert len(findings) == 0

    def test_check_name_and_description(self):
        check = CookieCheck()
        assert check.name == "cookie_check"
        assert check.description != ""


# ---------------------------------------------------------------------------
# TestCorsCheck
# ---------------------------------------------------------------------------


class TestCorsCheck:
    """Test the CORS misconfiguration passive check."""

    def test_detects_wildcard_origin(self):
        check = CorsCheck()
        findings = check.check(
            url="http://test.local",
            status_code=200,
            headers={"Access-Control-Allow-Origin": "*"},
            body="",
        )
        assert len(findings) >= 1
        assert any(f.check_name == "cors_wildcard_origin" for f in findings)

    def test_detects_wildcard_with_credentials(self):
        check = CorsCheck()
        findings = check.check(
            url="http://test.local",
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
            body="",
        )
        assert any(f.check_name == "cors_wildcard_credentials" for f in findings)
        crit = [f for f in findings if f.check_name == "cors_wildcard_credentials"]
        assert crit[0].severity == FindingSeverity.CRITICAL

    def test_wildcard_credentials_skips_lesser_findings(self):
        """When wildcard + credentials is found, it returns early (no wildcard_origin)."""
        check = CorsCheck()
        findings = check.check(
            url="http://test.local",
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
            body="",
        )
        names = [f.check_name for f in findings]
        assert "cors_wildcard_credentials" in names
        assert "cors_wildcard_origin" not in names

    def test_detects_null_origin(self):
        check = CorsCheck()
        findings = check.check(
            url="http://test.local",
            status_code=200,
            headers={"Access-Control-Allow-Origin": "null"},
            body="",
        )
        assert any(f.check_name == "cors_null_origin" for f in findings)

    def test_detects_origin_reflection_with_credentials(self):
        check = CorsCheck()
        findings = check.check(
            url="http://test.local",
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "https://evil.com",
                "Access-Control-Allow-Credentials": "true",
            },
            body="",
        )
        assert any(f.check_name == "cors_origin_reflection" for f in findings)

    def test_no_findings_without_cors_headers(self):
        check = CorsCheck()
        findings = check.check(
            url="http://test.local",
            status_code=200,
            headers={},
            body="",
        )
        assert len(findings) == 0

    def test_no_findings_for_specific_origin_without_credentials(self):
        """A specific origin without credentials is not flagged as origin reflection."""
        check = CorsCheck()
        findings = check.check(
            url="http://test.local",
            status_code=200,
            headers={"Access-Control-Allow-Origin": "https://trusted.com"},
            body="",
        )
        assert not any(f.check_name == "cors_origin_reflection" for f in findings)

    def test_check_name_and_description(self):
        check = CorsCheck()
        assert check.name == "cors_check"
        assert check.description != ""


# ---------------------------------------------------------------------------
# TestInformationCheck
# ---------------------------------------------------------------------------


class TestInformationCheck:
    """Test the information leakage passive check."""

    def test_detects_python_stack_trace(self):
        check = InformationCheck()
        body = "Traceback (most recent call last):\n  File '/app/main.py', line 42"
        findings = check.check(url="http://test.local", status_code=500, headers={}, body=body)
        assert any(f.check_name == "stack_trace_leak" for f in findings)

    def test_detects_java_stack_trace(self):
        check = InformationCheck()
        body = "at com.example.App(App.java:42)"
        findings = check.check(url="http://test.local", status_code=500, headers={}, body=body)
        assert any(f.check_name == "stack_trace_leak" for f in findings)

    def test_detects_php_error(self):
        check = InformationCheck()
        body = "Fatal error: Uncaught exception in /var/www/app.php on line 10"
        findings = check.check(url="http://test.local", status_code=500, headers={}, body=body)
        assert any(f.check_name == "stack_trace_leak" for f in findings)

    def test_detects_internal_ip(self):
        check = InformationCheck()
        body = "Connected to backend at 192.168.1.100 on port 5432"
        findings = check.check(url="http://test.local", status_code=200, headers={}, body=body)
        assert any(f.check_name == "internal_ip_leak" for f in findings)

    def test_detects_10_prefix_ip(self):
        check = InformationCheck()
        body = "Server: 10.0.0.5"
        findings = check.check(url="http://test.local", status_code=200, headers={}, body=body)
        assert any(f.check_name == "internal_ip_leak" for f in findings)

    def test_detects_email(self):
        check = InformationCheck()
        body = "Contact admin@company.com for support"
        findings = check.check(url="http://test.local", status_code=200, headers={}, body=body)
        assert any(f.check_name == "email_leak" for f in findings)

    def test_detects_example_emails(self):
        """The information check detects any email pattern (no filtering of @example.com)."""
        check = InformationCheck()
        body = "Email: user@example.com or test@test.invalid"
        findings = check.check(url="http://test.local", status_code=200, headers={}, body=body)
        # Current implementation does not filter out example domains
        assert any(f.check_name == "email_leak" for f in findings)

    def test_detects_unix_file_path(self):
        check = InformationCheck()
        body = "Error loading config from /etc/myapp/config.yml"
        findings = check.check(url="http://test.local", status_code=200, headers={}, body=body)
        assert any(f.check_name == "file_path_leak" for f in findings)

    def test_detects_windows_file_path(self):
        check = InformationCheck()
        body = r"Loading C:\Users\admin\Documents\app.exe"
        findings = check.check(url="http://test.local", status_code=200, headers={}, body=body)
        assert any(f.check_name == "file_path_leak" for f in findings)

    def test_detects_openai_api_key(self):
        check = InformationCheck()
        body = "config = {api_key: 'sk-1234567890abcdefghijklmno'}"
        findings = check.check(url="http://test.local", status_code=200, headers={}, body=body)
        assert any(f.check_name == "api_key_leak" for f in findings)
        # API key leaks should be CRITICAL
        api_findings = [f for f in findings if f.check_name == "api_key_leak"]
        assert api_findings[0].severity == FindingSeverity.CRITICAL

    def test_detects_aws_access_key(self):
        check = InformationCheck()
        body = "aws_key = AKIAIOSFODNN7EXAMPLE"
        findings = check.check(url="http://test.local", status_code=200, headers={}, body=body)
        assert any(f.check_name == "api_key_leak" for f in findings)

    def test_detects_bearer_token(self):
        """Bearer tokens are detected as API key leaks."""
        check = InformationCheck()
        body = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        findings = check.check(url="http://test.local", status_code=200, headers={}, body=body)
        assert any(f.check_name == "api_key_leak" for f in findings)

    def test_detects_sql_error(self):
        check = InformationCheck()
        body = "You have an error in your SQL syntax near 'SELECT'"
        findings = check.check(url="http://test.local", status_code=500, headers={}, body=body)
        assert any(f.check_name == "sql_error_leak" for f in findings)

    def test_detects_debug_mode(self):
        check = InformationCheck()
        body = "DEBUG = True\nsettings loaded"
        findings = check.check(url="http://test.local", status_code=200, headers={}, body=body)
        assert any(f.check_name == "debug_mode_enabled" for f in findings)

    def test_detects_flask_debug(self):
        check = InformationCheck()
        body = "FLASK_DEBUG=1"
        findings = check.check(url="http://test.local", status_code=200, headers={}, body=body)
        assert any(f.check_name == "debug_mode_enabled" for f in findings)

    def test_no_findings_on_clean_body(self):
        check = InformationCheck()
        body = "<html><body><h1>Welcome</h1></body></html>"
        findings = check.check(url="http://test.local", status_code=200, headers={}, body=body)
        assert len(findings) == 0

    def test_no_findings_on_empty_body(self):
        check = InformationCheck()
        findings = check.check(url="http://test.local", status_code=200, headers={}, body="")
        assert len(findings) == 0

    def test_check_name_and_description(self):
        check = InformationCheck()
        assert check.name == "information_check"
        assert check.description != ""

    def test_api_key_evidence_is_redacted(self):
        """API key evidence should be truncated to avoid full key exposure."""
        check = InformationCheck()
        body = "key: sk-abcdefghijklmnopqrstuvwxyz1234567890"
        findings = check.check(url="http://test.local", status_code=200, headers={}, body=body)
        api_findings = [f for f in findings if f.check_name == "api_key_leak"]
        assert len(api_findings) >= 1
        # Evidence should be truncated (ends with ...)
        assert "..." in api_findings[0].evidence
