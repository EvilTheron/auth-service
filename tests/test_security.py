from auth_service.core.security import hash_password, verify_password


def test_hash_is_not_plain_and_verifies():
    password_hash = hash_password("secret-password")
    assert password_hash != "secret-password"
    assert verify_password("secret-password", password_hash)
    assert not verify_password("other-password", password_hash)


def test_same_password_gives_different_hashes():
    assert hash_password("secret-password") != hash_password("secret-password")
