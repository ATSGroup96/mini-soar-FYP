"""
TLS/SSL certificate checker.

For each in-scope host:port offering TLS, pull the leaf certificate and report
expiry, self-signed status, weak signature algorithms, and negotiated TLS
version. Pure inspection — it opens a TLS socket and reads the cert, nothing
more.
"""
from __future__ import annotations

import ssl
import socket
from dataclasses import dataclass
from datetime import datetime, timezone

from common.allowlist import assert_in_scope
from common.audit import log_event

WEAK_SIG_ALGS = {"md5", "sha1"}
COMMON_TLS_PORTS = (443, 8443, 993, 995, 465, 990, 636, 5061)
# services that upgrade a plain connection to TLS (STARTTLS-style)
SMTP_STARTTLS_PORTS = (25, 587)
POSTGRES_PORTS = (5432,)


@dataclass
class CertInfo:
    ip: str
    port: int
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    days_to_expiry: int | None = None
    is_self_signed: bool = False
    is_expired: bool = False
    weak_sig_alg: str = ""
    tls_version: str = ""


def _name_to_str(name) -> str:
    try:
        parts = []
        for rdn in name:
            for k, v in rdn:
                parts.append(f"{k}={v}")
        return ", ".join(parts)
    except Exception:
        return str(name)


def _inspect_ctx() -> ssl.SSLContext:
    """Permissive client context: we only READ the certificate, so we must be
    able to talk to old servers (TLS 1.0, weak ciphers) to report on them."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we inspect, we don't trust-validate
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (ValueError, AttributeError):
        pass
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


def _starttls_smtp(sock: socket.socket) -> bool:
    f = sock.makefile("rb")
    if not f.readline().startswith(b"220"):
        return False
    sock.sendall(b"EHLO mini-soar\r\n")
    while True:
        line = f.readline()
        if not line or line[3:4] != b"-":
            break
    sock.sendall(b"STARTTLS\r\n")
    return f.readline().startswith(b"220")


def _starttls_postgres(sock: socket.socket) -> bool:
    # SSLRequest: int32 length 8, int32 code 80877103; server answers 'S' or 'N'
    sock.sendall((8).to_bytes(4, "big") + (80877103).to_bytes(4, "big"))
    return sock.recv(1) == b"S"


def check_cert(ip: str, port: int) -> CertInfo | None:
    assert_in_scope(ip)
    ctx = _inspect_ctx()

    info = CertInfo(ip=ip, port=port)
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            if port in SMTP_STARTTLS_PORTS and not _starttls_smtp(sock):
                return None
            if port in POSTGRES_PORTS and not _starttls_postgres(sock):
                return None
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                info.tls_version = ssock.version() or ""
                der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
    except Exception:
        return None

    # parse via cryptography for sig alg + precise fields
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        xc = x509.load_der_x509_certificate(der)
        info.subject = xc.subject.rfc4514_string()
        info.issuer = xc.issuer.rfc4514_string()
        info.is_self_signed = (xc.subject == xc.issuer)
        nb = xc.not_valid_before_utc
        na = xc.not_valid_after_utc
        info.not_before = nb.isoformat()
        info.not_after = na.isoformat()
        now = datetime.now(timezone.utc)
        info.days_to_expiry = (na - now).days
        info.is_expired = na < now
        alg = (xc.signature_hash_algorithm.name.lower()
               if isinstance(xc.signature_hash_algorithm, hashes.HashAlgorithm)
               else "")
        if any(w in alg for w in WEAK_SIG_ALGS):
            info.weak_sig_alg = xc.signature_algorithm_oid._name
    except Exception:
        # fall back to the ssl module's parsed dict
        if cert:
            info.subject = _name_to_str(cert.get("subject", []))
            info.issuer = _name_to_str(cert.get("issuer", []))

    log_event("engine", "tls.check", f"{ip}:{port}",
              {"expiry_days": info.days_to_expiry,
               "self_signed": info.is_self_signed,
               "weak": info.weak_sig_alg})
    return info


def check_host(ip: str, services) -> list[CertInfo]:
    """Check TLS on any service that looks like it speaks TLS."""
    assert_in_scope(ip)
    results: list[CertInfo] = []
    seen: set[int] = set()
    for svc in services:
        name = (svc.service_name or "").lower()
        tls_like = (
            svc.port in COMMON_TLS_PORTS
            or svc.port in SMTP_STARTTLS_PORTS or svc.port in POSTGRES_PORTS
            or name in ("smtp", "postgresql")
            or "ssl" in name or "https" in name or "tls" in name
        )
        if tls_like and svc.port not in seen:
            seen.add(svc.port)
            ci = check_cert(ip, svc.port)
            if ci:
                results.append(ci)
    return results
