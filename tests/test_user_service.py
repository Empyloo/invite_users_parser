# tests/test_user_service.py
import pytest
import freezegun
from unittest.mock import patch
import jwt
import requests
import datetime
from src.user_service import AdminUserService


@pytest.fixture
def user_service():
    return AdminUserService(
        base_url="https://example.com",
        anon_key="anon_key",
        service_key="service_key",
    )


@patch("requests.get")
def test_get_user_by_id(mock_get, user_service):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"user_id": "user_id"}
    response = user_service.get_user_by_id("user_id")
    assert response.status_code == 200
    assert response.json() == {"user_id": "user_id"}


@patch("requests.post")
def test_generate_link(mock_post, user_service):
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {"link": "link"}
    response = user_service.generate_link()
    assert response.status_code == 200
    assert response.json() == {"link": "link"}


@patch("requests.delete")
def test_delete_user(mock_delete, user_service):
    mock_delete.return_value.status_code = 200
    mock_delete.return_value.json.return_value = {"user_id": "user_id"}
    response = user_service.delete_user("user_id")
    assert response.status_code == 200
    assert response.json() == {"user_id": "user_id"}


def test_is_jwt_valid(user_service):
    with freezegun.freeze_time("2022-01-01"):
        jwt_token = jwt.encode(
            {"sub": "user_id", "exp": datetime.datetime.utcnow().timestamp() + 100},
            "secret",
            algorithm="HS256",
        )
        assert user_service.is_jwt_valid(jwt_token) == {
            "sub": "user_id",
            "exp": datetime.datetime.strptime("2022-01-01", "%Y-%m-%d").timestamp()
            + 100,
        }


@patch("requests.get")
def test_verify_user(mock_get, user_service):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "user_id": "user_id",
        "user_metadata": {"role": "super_admin"},
    }
    with freezegun.freeze_time("2022-01-01"):
        jwt_token = jwt.encode(
            {"sub": "user_id", "exp": datetime.datetime.utcnow().timestamp() + 100},
            "secret",
            algorithm="HS256",
        )
        assert user_service.verify_user(jwt_token) == {"role": "super_admin"}


def test_verify_user_invalid_jwt(user_service):
    jwt_token = "invalid_jwt_token"
    result = user_service.verify_user(jwt_token)
    assert result == {"error": "Invalid JWT"}


@patch("requests.get")
def test_get_user_by_id_error(mock_get, user_service):
    mock_get.return_value.status_code = 404
    mock_get.return_value.json.return_value = {"error": "User not found"}
    response = user_service.get_user_by_id("user_id")
    assert response.status_code == 404
    assert response.json() == {"error": "User not found"}


@patch("requests.get")
def test_user_metadata_returns_none(mock_get, user_service):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"user_id": "user_id"}
    response = user_service.get_user_by_id("user_id")
    assert response.status_code == 200
    assert response.json().get("user_metadata") is None


@patch("requests.get")
def test_user_not_super_admin(mock_get, user_service):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "user_id": "user_id",
        "user_metadata": {"role": "admin"},
    }
    with freezegun.freeze_time("2022-01-01"):
        jwt_token = jwt.encode(
            {"sub": "user_id", "exp": datetime.datetime.utcnow().timestamp() + 100},
            "secret",
            algorithm="HS256",
        )
        result = user_service.verify_user(jwt_token)
        assert result == {"error": "User is not a super admin"}
