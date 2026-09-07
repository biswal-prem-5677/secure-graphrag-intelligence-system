import pytest
from app.models.user import User, UserRole, user_store
from app.security.auth import (
    create_access_token,
    decode_token,
    hash_password,
    seed_default_users,
    verify_password,
)


def test_password_hashing_and_verification():
    password = "ComplexP@ssw0rd!2024"
    hashed = hash_password(password)
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_jwt_generation_and_decoding():
    token = create_access_token({"sub": "analyst_test", "role": "analyst"})
    payload = decode_token(token)
    assert payload["sub"] == "analyst_test"
    assert payload["role"] == "analyst"
    assert "exp" in payload


def test_tampered_token_rejected():
    token = create_access_token({"sub": "admin", "role": "admin"})
    tampered = token[:-5] + "XXXXX"
    with pytest.raises(Exception):
        decode_token(tampered)


def test_seed_default_users():
    seed_default_users()
    assert user_store.user_exists("admin") is True
    assert user_store.user_exists("analyst") is True
    admin = user_store.get_user("admin")
    assert admin.role == UserRole.admin
