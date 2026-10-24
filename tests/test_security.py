import pytest
from pydantic import ValidationError

from auth_service.core.config import Settings
from auth_service.core.security import hash_password, verify_password


def test_hash_is_not_plain_and_verifies():
    password_hash = hash_password("secret-password")
    assert password_hash != "secret-password"
    assert verify_password("secret-password", password_hash)
    assert not verify_password("other-password", password_hash)


def test_same_password_gives_different_hashes():
    assert hash_password("secret-password") != hash_password("secret-password")


def test_weak_jwt_secret_is_rejected():
    with pytest.raises(ValidationError):
        Settings(
            postgres_user="u",
            postgres_password="p",
            postgres_db="d",
            jwt_secret="short",
        )
