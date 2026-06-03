"""TLS CA certificate generation for HTTPS interception.

Attempts to reuse mitmproxy's built-in CA infrastructure first.  If
mitmproxy is not installed, falls back to the ``cryptography`` library.
If neither is available the manager still works -- it simply reports
that no CA is available and provides installation instructions.
"""

from __future__ import annotations

import logging
import platform
from datetime import UTC, datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


class CertificateManager:
    """Manages the root CA certificate used by the MITM proxy."""

    def __init__(self, cert_dir: str = "data/proxy") -> None:
        self.cert_dir = Path(cert_dir)
        self.ca_cert_path = self.cert_dir / "ca-cert.pem"
        self.ca_key_path = self.cert_dir / "ca-key.pem"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ensure_ca(self) -> Path | None:
        """Generate a CA certificate if one does not already exist.

        Tries the following strategies in order:

        1. If the cert files already exist on disk, return immediately.
        2. Use mitmproxy's CA (it auto-generates one in ``~/.mitmproxy``).
        3. Use the ``cryptography`` library to self-sign a CA.
        4. Return *None* with a warning if nothing is available.
        """
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            logger.info("CA certificate already exists: %s", self.ca_cert_path)
            return self.ca_cert_path

        self.cert_dir.mkdir(parents=True, exist_ok=True)

        # Strategy 1: mitmproxy CA ------------------------------------------
        path = self._try_mitmproxy_ca()
        if path is not None:
            return path

        # Strategy 2: cryptography library ----------------------------------
        path = self._try_cryptography_ca()
        if path is not None:
            return path

        # Nothing available -------------------------------------------------
        logger.warning(
            "Cannot generate CA certificate.  Install mitmproxy or "
            "the cryptography library:\n"
            "  pip install mitmproxy>=10.0\n"
            "  pip install cryptography>=41.0"
        )
        return None

    def get_cert_path(self) -> Path | None:
        """Return the CA certificate path if it exists on disk."""
        if self.ca_cert_path.exists():
            return self.ca_cert_path
        return None

    def get_install_instructions(self) -> str:
        """Return human-readable instructions for trusting the CA cert."""
        cert = self.ca_cert_path
        system = platform.system()

        lines = [
            "To trust the RedSimulator CA certificate for HTTPS interception:",
            "",
            f"  Certificate location: {cert}",
            "",
        ]

        if system == "Darwin":
            lines.extend(
                [
                    "  macOS:",
                    f'    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "{cert}"',
                    "",
                ]
            )
        elif system == "Linux":
            lines.extend(
                [
                    "  Linux (Debian / Ubuntu):",
                    f'    sudo cp "{cert}" /usr/local/share/ca-certificates/redsimulator-ca.crt',
                    "    sudo update-ca-certificates",
                    "",
                    "  Linux (RHEL / Fedora):",
                    f'    sudo cp "{cert}" /etc/pki/ca-trust/source/anchors/redsimulator-ca.crt',
                    "    sudo update-ca-trust",
                    "",
                ]
            )
        elif system == "Windows":
            lines.extend(
                [
                    "  Windows:",
                    f'    certutil -addstore -f "ROOT" "{cert}"',
                    "",
                ]
            )

        lines.extend(
            [
                "  Firefox (all platforms):",
                "    Settings > Privacy & Security > Certificates > View Certificates",
                "    > Authorities > Import > select the .pem file",
                "",
                "  Chrome / Edge (all platforms):",
                "    Settings > Privacy and Security > Security > Manage certificates",
                "    > Authorities > Import > select the .pem file",
            ]
        )

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private strategies
    # ------------------------------------------------------------------

    def _try_mitmproxy_ca(self) -> Path | None:
        """Copy mitmproxy's auto-generated CA files if available."""
        try:
            from mitmproxy.certs import CertStore  # type: ignore[import-untyped]

            mitmproxy_dir = Path.home() / ".mitmproxy"
            mitm_cert = mitmproxy_dir / "mitmproxy-ca-cert.pem"
            mitm_key = mitmproxy_dir / "mitmproxy-ca.pem"

            if not mitm_cert.exists():
                # Let mitmproxy generate its CA by instantiating the store.
                mitmproxy_dir.mkdir(parents=True, exist_ok=True)
                CertStore.from_store(str(mitmproxy_dir), "mitmproxy")
                logger.info("mitmproxy CA generated at %s", mitmproxy_dir)

            if mitm_cert.exists() and mitm_key.exists():
                import shutil

                shutil.copy2(mitm_cert, self.ca_cert_path)
                shutil.copy2(mitm_key, self.ca_key_path)
                logger.info(
                    "CA certificate copied from mitmproxy: %s",
                    self.ca_cert_path,
                )
                return self.ca_cert_path

        except ImportError:
            logger.debug("mitmproxy not installed -- skipping mitmproxy CA strategy")
        except Exception as exc:
            logger.debug("mitmproxy CA strategy failed: %s", exc)

        return None

    def _try_cryptography_ca(self) -> Path | None:
        """Generate a self-signed CA using the ``cryptography`` library."""
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
        except ImportError:
            logger.debug("cryptography library not installed -- skipping")
            return None

        try:
            # Generate RSA key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "CA"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RedSimulator"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "RedSimulator Proxy CA"),
                ]
            )

            now = datetime.now(UTC)
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_cert_sign=True,
                        crl_sign=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .sign(key, hashes.SHA256())
            )

            # Write cert
            self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

            # Write key
            self.ca_key_path.write_bytes(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

            logger.info(
                "CA certificate generated with cryptography library: %s",
                self.ca_cert_path,
            )
            return self.ca_cert_path

        except Exception as exc:
            logger.error("Failed to generate CA certificate: %s", exc)
            return None
