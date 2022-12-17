# test_main.py
import pytest
import unittest
import pandas as pd
from unittest.mock import patch, Mock, AsyncMock
from main import (
    verify_user,
    load_emails_from_csv,
    invite_users,
    invite_user,
    get_secret_payload,
)


@patch("google.cloud.secretmanager.SecretManagerServiceClient")
def test_get_secret_payload(mock_client):
    # Test the case where the secret version is accessed successfully
    mock_response = Mock()
    mock_response.payload.data = b"my-secret-payload"
    mock_response.payload.data_crc32c = 1090118340
    mock_client.return_value.access_secret_version.return_value = mock_response

    get_secret_payload("my-project", "my-secret", "5")
    mock_client.return_value.access_secret_version.assert_called_with(
        request={"name": "projects/my-project/secrets/my-secret/versions/5"}
    )
    assert get_secret_payload("my-project", "my-secret", "5") == "my-secret-payload"


@patch("google.cloud.secretmanager.SecretManagerServiceClient")
def test_get_secret_payload_invalid_project_id(mock_client):
    # Test the case where the project_id is invalid
    mock_client.return_value.access_secret_version.side_effect = Exception(
        "Project not found"
    )
    assert get_secret_payload("invalid-project", "my-secret", "5") is None


@patch("main.Client")
def test_verify_user_valid_token(mock_supabase):
    # Test the case where the JWT token is valid and the user is returned successfully
    mock_user = {"id": 1, "email": "user@example.com"}
    mock_supabase.auth.api.get_user.return_value = mock_user
    assert verify_user(mock_supabase, "valid-token") == mock_user


@patch("main.Client")
def test_verify_user_exception(mock_supabase):
    # Test the case where there is an exception raised when trying to verify the JWT token
    mock_supabase.auth.api.get_user.side_effect = Exception("Invalid token")
    assert verify_user(mock_supabase, "invalid-token") is None

def test_load_emails_from_csv_valid_file():
    # Test the case where the CSV file is valid and contains a list of email addresses
    mock_csv = "emails.csv"
    with patch("main.pd.read_csv", return_value=pd.DataFrame({"emails": ["user1@example.com", "user2@example.com"]})):
        emails = load_emails_from_csv(mock_csv)
        assert emails == ["user1@example.com", "user2@example.com"]

def test_load_emails_from_csv_missing_column():
    # Test the case where the CSV file is valid but does not contain a column named "emails"
    mock_csv = "emails.csv"
    with patch("main.pd.read_csv", return_value=pd.DataFrame({"email": ["user1@example.com", "user2@example.com"]})):
        emails = load_emails_from_csv(mock_csv)
        assert emails == []

def test_load_emails_from_csv_exception():
    # Test the case where there is an exception raised when trying to read the CSV file
    mock_csv = "emails.csv"
    with patch("main.pd.read_csv", side_effect=Exception("Error reading CSV file")):
        emails = load_emails_from_csv(mock_csv)
        assert emails == []


async def test_invite_user_success(anyio_backend):
    # Test the case where the invite request is successful
    mock_email = "user@example.com"
    mock_data = {"company_id": 1}
    mock_supabase_client = AsyncMock()
    result = await invite_user(mock_supabase_client, mock_email, mock_data)
    assert result is None

@pytest.mark.asyncio
async def test_invite_user_max_attempts():
    # Test the case where the invite request fails after the maximum number of attempts
    mock_email = "user@example.com"
    mock_data = {"company_id": 1}
    mock_supabase_client = Mock(side_effect=Exception("Error inviting user"))
    result = await invite_user(mock_supabase_client, mock_email, mock_data)
    assert result == mock_email

@pytest.mark.asyncio
async def test_invite_user_custom_role():
    # Test the case where the invite request is successful
    mock_email = "user@example.com"
    mock_data = {"company_id": 1}
    mock_role = "admin"
    mock_supabase_client = Mock()
    result = await invite_user(mock_supabase_client, mock_email, mock_data, role=mock_role)
    mock_supabase_client.auth.api.invite_user_by_email.assert_called_with(email=mock_email, data={"company_id": 1, "role": mock_role})
