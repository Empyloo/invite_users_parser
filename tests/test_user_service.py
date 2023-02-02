import pytest
from unittest.mock import patch

from src.user_service import UserService


@patch("requests.get")
def test_verify_user_success(mock_get):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"email": "test@example.com"}

    service = UserService("https://api.example.com", "secret-anon-key")
    result = service.verify_user("test-jwt-token")

    assert result == {"email": "test@example.com"}


@patch("requests.get")
def test_verify_user_failure(mock_get):
    mock_get.return_value.status_code = 401

    service = UserService("https://api.example.com", "secret-anon-key")
    result = service.verify_user("test-jwt-token")

    assert result is None


@patch("requests.get")
def test_get_user_details_success(mock_get):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "email": "test@example.com",
        "name": "Test User",
    }

    service = UserService("https://api.example.com", "secret-anon-key")
    result = service.get_user_details("test-jwt-token")
    assert result == {"email": "test@example.com", "name": "Test User"}


@patch("requests.get")
def test_get_user_details_failure(mock_get):
    mock_get.return_value.status_code = 401
    service = UserService("https://api.example.com", "secret-anon-key")
    result = service.get_user_details("test-jwt-token")

    assert result is None


@patch("requests.patch")
def test_update_user_details_success(mock_patch):
    mock_patch.return_value.status_code = 200
    mock_patch.return_value.json.return_value = {
        "email": "test@example.com",
        "name": "Updated User",
    }
    service = UserService("https://api.example.com", "secret-anon-key")
    result = service.update_user_details("test-jwt-token", {"name": "Updated User"})

    assert result == {"email": "test@example.com", "name": "Updated User"}


@patch("requests.patch")
def test_update_user_details_failure(mock_patch):
    mock_patch.return_value.status_code = 401
    service = UserService("https://api.example.com", "secret-anon-key")
    result = service.update_user_details("test-jwt-token", {"name": "Updated User"})

    assert result is None
