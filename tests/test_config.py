import ssl

import pytest

from auth_service.core.config import Settings

BASE = {
    "postgres_user": "auth",
    "postgres_password": "secret",
    "postgres_db": "auth_service",
    "jwt_secret": "x" * 32,
}


def test_database_tls_is_off_by_default():
    assert Settings(**BASE, _env_file=None).database_connect_args == {}  # type: ignore[arg-type]


def test_database_tls_require_encrypts_without_verification():
    settings = Settings(**BASE, postgres_ssl_mode="require", _env_file=None)  # type: ignore[arg-type]
    assert settings.database_connect_args == {"ssl": "require"}


def test_database_tls_verify_full_checks_certificate_and_host():
    settings = Settings(**BASE, postgres_ssl_mode="verify-full", _env_file=None)  # type: ignore[arg-type]
    context = settings.database_connect_args["ssl"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_unknown_tls_mode_is_rejected():
    with pytest.raises(ValueError):
        Settings(**BASE, postgres_ssl_mode="sometimes", _env_file=None)  # type: ignore[arg-type]
