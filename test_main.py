# test_main.py
import pytest
import unittest
import pandas as pd
from unittest.mock import patch, Mock, AsyncMock
from main import (
    verify_user,
    load_emails_from_csv,
    invite_users_adapter,
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
    # Test the case where the JWT token is valid and the user is returned
    # successfully
    mock_user = {"id": 1, "email": "user@example.com"}
    mock_supabase.auth.api.get_user.return_value = mock_user
    assert verify_user(mock_supabase, "valid-token") == mock_user


@patch("main.Client")
def test_verify_user_exception(mock_supabase):
    # Test the case where there is an exception raised when trying to verify
    # the JWT token
    mock_supabase.auth.api.get_user.side_effect = Exception("Invalid token")
    assert verify_user(mock_supabase, "invalid-token") is None


def test_load_emails_from_csv_valid_file():
    # Test the case where the CSV file is valid and contains a list of
    # email addresses
    mock_csv = "emails.csv"
    with patch(
        "main.pd.read_csv",
        return_value=pd.DataFrame(
            {"emails": ["user1@example.com", "user2@example.com"]}
        ),
    ):
        emails = load_emails_from_csv(mock_csv)
        assert emails == ["user1@example.com", "user2@example.com"]


def test_load_emails_from_csv_missing_column():
    # Test the case where the CSV file is valid but does not contain a column
    # amed "emails"
    mock_csv = "emails.csv"
    with patch(
        "main.pd.read_csv",
        return_value=pd.DataFrame(
            {"email": ["user1@example.com", "user2@example.com"]}
        ),
    ):
        emails = load_emails_from_csv(mock_csv)
        assert emails == []


def test_load_emails_from_csv_exception():
    # Test the case where there is an exception raised when trying to read the
    # CSV file
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
    mock_supabase_client.auth.api.invite_user_by_email.assert_called_with(
        email=mock_email, data={"company_id": 1, "role": "user"}
    )


@pytest.mark.asyncio
async def test_invite_user_max_attempts():
    # Test the case where the invite request fails after the maximum number
    # of attempts
    mock_email = "user@example.com"
    mock_data = {"company_id": 1}
    mock_supabase_client = Mock(side_effect=Exception("Error inviting user"))
    result = await invite_user(mock_supabase_client, mock_email, mock_data)
    assert result == mock_email


@pytest.mark.asyncio
async def test_invite_user_custom_role():
    # Test the case where admin invite request is successful
    mock_email = "user@example.com"
    mock_data = {"company_id": 1}
    mock_role = "admin"
    mock_supabase_client = Mock()
    result = await invite_user(
        mock_supabase_client, mock_email, mock_data, role=mock_role
    )
    mock_supabase_client.auth.api.invite_user_by_email.assert_called_with(
        email=mock_email, data={"company_id": 1, "role": mock_role}
    )


@pytest.mark.asyncio
async def test_invite_users_adapter():
    # Set up test data
    request = unittest.mock.Mock(headers={"Authorization": "fake-jwt-token"})
    request.get_json.return_value = {
        "emails": ["user1@example.com", "user2@example.com"]
    }

    # Patch the verify_user, load_emails_from_csv, and invite_user functions
    with unittest.mock.patch(
        "main.verify_user"
    ) as mock_verify_user, unittest.mock.patch(
        "main.load_emails_from_csv"
    ) as mock_load_emails_from_csv, unittest.mock.patch(
        "main.invite_user"
    ) as mock_invite_user:
        mock_user = {
            "id": 1,
            "email": "user@example.com",
            "app_metadata": {"fake": "data"},
        }
        mock_verify_user.return_value = mock_user
        mock_load_emails_from_csv.return_value = [
            "user1@example.com",
            "user2@example.com",
        ]
        mock_invite_user.return_value = None

        response = await invite_users_adapter(request)
        message, status_code = response

        assert status_code == 200
        assert message == "Invitation sent"


@pytest.mark.asyncio
async def test_invite_users_adapter_invalid_jwt_token():
    # Set up test data
    request = unittest.mock.Mock(headers={"Authorization": "fake-jwt-token"})
    request.get_json.return_value = {
        "emails": ["user1@example.com", "user2@example.com"]
    }

    # Patch the verify_user function
    with unittest.mock.patch("main.verify_user") as mock_verify_user:
        mock_verify_user.return_value = None

        response = await invite_users_adapter(request)
        message, status_code = response

        assert status_code == 401
        assert message == "Unauthorized"


@pytest.mark.asyncio
async def test_invite_users_adapter_invalid_request_body():
    # Set up test data
    request = unittest.mock.Mock(headers={"Authorization": "fake-jwt-token"})
    request.get_json.return_value = {}

    # Patch the verify_user function
    with unittest.mock.patch("main.verify_user") as mock_verify_user:
        mock_user = {
            "id": 1,
            "email": "user@example.com",
            "app_metadata": {"fake": "data"},
        }
        mock_verify_user.return_value = mock_user

        response = await invite_users_adapter(request)
        message, status_code = response

        assert status_code == 400
        assert message == "Invalid request body"


@pytest.mark.asyncio
async def test_invite_users_adapter_csv_file_not_found():
    # Set up test data
    request = unittest.mock.Mock(headers={"Authorization": "fake-jwt-token"})
    request.get_json.return_value = {"csv_file": "fake-file.csv"}
    # Patch the verify_user and load_emails_from_csv functions
    with unittest.mock.patch(
        "main.verify_user"
    ) as mock_verify_user, unittest.mock.patch(
        "main.load_emails_from_csv"
    ) as mock_load_emails_from_csv:
        mock_user = {
            "id": 1,
            "email": "user@example.com",
            "app_metadata": {"fake": "data"},
        }
        mock_verify_user.return_value = mock_user
        mock_load_emails_from_csv.return_value = []  # FileNotFoundError

        response = await invite_users_adapter(request)
        message, status_code = response

        assert status_code == 400
        assert message == "CSV file not found, invalid or empty"


@pytest.mark.asyncio
async def test_invite_users_adapter_no_emails_provided():
    # Set up test data
    request = unittest.mock.Mock(headers={"Authorization": "fake-jwt-token"})
    request.get_json.return_value = {}

    # Patch the verify_user function
    with unittest.mock.patch("main.verify_user") as mock_verify_user:
        mock_user = {
            "id": 1,
            "email": "user@example.com",
            "app_metadata": {"fake": "data"},
        }
        mock_verify_user.return_value = mock_user

        response = await invite_users_adapter(request)
        message, status_code = response

        assert status_code == 400
        assert message == "Invalid request body"


@pytest.mark.asyncio
async def test_invite_users_adapter_emails_with_errors():
    # Set up test data
    request = unittest.mock.Mock(headers={"Authorization": "fake-jwt-token"})
    request.get_json.return_value = {
        "emails": ["user1@example.com", "user2@example.com"]
    }

    with unittest.mock.patch(
        "main.verify_user"
    ) as mock_verify_user, unittest.mock.patch(
        "main.load_emails_from_csv"
    ) as mock_load_emails_from_csv, unittest.mock.patch(
        "main.invite_user"
    ) as mock_invite_user:
        mock_user = {
            "id": 1,
            "email": "user@example.com",
            "app_metadata": {"fake": "data"},
        }
        mock_verify_user.return_value = mock_user
        mock_load_emails_from_csv.return_value = [
            "user1@example.com",
            "user2@example.com",
        ]
        mock_invite_user.side_effect = [None, "user2@example.com"]

        response = await invite_users_adapter(request)
        message, status_code = response

        assert status_code == 200
        assert (
            message == "Invitation sent, with errors for emails: ['user2@example.com']"
        )


@pytest.mark.asyncio
async def test_invite_users_adapter_csv_file_only():
    # Set up test data
    request = unittest.mock.Mock(headers={"Authorization": "fake-jwt-token"})
    request.get_json.return_value = {"csv_file": "fake-csv-file.csv"}
    # Patch the verify_user, load_emails_from_csv, and invite_user functions
    with unittest.mock.patch(
        "main.verify_user"
    ) as mock_verify_user, unittest.mock.patch(
        "main.load_emails_from_csv"
    ) as mock_load_emails_from_csv, unittest.mock.patch(
        "main.invite_user"
    ) as mock_invite_user:
        mock_user = {
            "id": 1,
            "email": "user@example.com",
            "app_metadata": {"fake": "data"},
        }
        mock_verify_user.return_value = mock_user
        mock_load_emails_from_csv.return_value = [
            "user1@example.com",
            "user2@example.com",
        ]
        mock_invite_user.return_value = None

        response = await invite_users_adapter(request)
        message, status_code = response

        assert status_code == 200
        assert message == "Invitation sent"


@pytest.mark.asyncio
async def test_invite_users_adapter_csv_file_and_emails():
    # Set up test data
    request = unittest.mock.Mock(headers={"Authorization": "fake-jwt-token"})
    request.get_json.return_value = {
        "emails": ["user1@example.com"],
        "csv_file": "fake-csv-file-contents",
    }
    # Patch the verify_user, load_emails_from_csv, and invite_user functions
    with unittest.mock.patch(
        "main.verify_user"
    ) as mock_verify_user, unittest.mock.patch(
        "main.load_emails_from_csv"
    ) as mock_load_emails_from_csv, unittest.mock.patch(
        "main.invite_user"
    ) as mock_invite_user:
        mock_user = {
            "id": 1,
            "email": "user@example.com",
            "app_metadata": {"fake": "data"},
        }
        mock_verify_user.return_value = mock_user
        mock_load_emails_from_csv.return_value = [
            "user2@example.com",
            "user3@example.com",
        ]
        mock_invite_user.return_value = None

        response = await invite_users_adapter(request)
        message, status_code = response

        assert status_code == 200
        assert message == "Invitation sent"
        assert mock_load_emails_from_csv.call_count == 1
        assert mock_invite_user.call_count == 3
        mock_invite_user.assert_any_call(
            unittest.mock.ANY, "user3@example.com", unittest.mock.ANY, unittest.mock.ANY
        )
        mock_invite_user.assert_any_call(
            unittest.mock.ANY, "user2@example.com", {"fake": "data"}, unittest.mock.ANY
        )
        mock_invite_user.assert_any_call(
            unittest.mock.ANY, "user3@example.com", {"fake": "data"}, unittest.mock.ANY
        )


@pytest.mark.asyncio
async def test_invite_users_adapter_custom_role():
    # Set up test data
    request = unittest.mock.Mock(headers={"Authorization": "fake-jwt-token"})
    request.get_json.return_value = {
        "emails": ["user1@example.com", "user2@example.com"],
        "role": "admin",
    }
    # Patch the verify_user, load_emails_from_csv, and invite_user functions
    with unittest.mock.patch(
        "main.verify_user"
    ) as mock_verify_user, unittest.mock.patch(
        "main.load_emails_from_csv"
    ) as mock_load_emails_from_csv, unittest.mock.patch(
        "main.invite_user"
    ) as mock_invite_user:
        mock_user = {
            "id": 1,
            "email": "user@example.com",
            "app_metadata": {"fake": "data"},
        }
        mock_verify_user.return_value = mock_user
        mock_load_emails_from_csv.return_value = [
            "user1@example.com",
            "user2@example.com",
        ]
        mock_invite_user.return_value = None

        response = await invite_users_adapter(request)
        message, status_code = response

        assert status_code == 200
        assert message == "Invitation sent"
        assert mock_invite_user.call_count == 2
        mock_invite_user.assert_any_call(
            unittest.mock.ANY, "user1@example.com", unittest.mock.ANY, "admin"
        )
        mock_invite_user.assert_any_call(
            unittest.mock.ANY, "user2@example.com", unittest.mock.ANY, "admin"
        )


@pytest.mark.asyncio
async def test_invite_users_adapter_default_role():
    # Set up test data
    request = unittest.mock.Mock(headers={"Authorization": "fake-jwt-token"})
    request.get_json.return_value = {
        "emails": ["user1@example.com"],
    }
    # Patch the verify_user, load_emails_from_csv, and invite_user functions
    with unittest.mock.patch(
        "main.verify_user"
    ) as mock_verify_user, unittest.mock.patch(
        "main.load_emails_from_csv"
    ) as mock_load_emails_from_csv, unittest.mock.patch(
        "main.invite_user"
    ) as mock_invite_user:
        mock_user = {
            "id": 1,
            "email": "user@example.com",
            "app_metadata": {"fake": "data"},
        }
        mock_verify_user.return_value = mock_user
        mock_load_emails_from_csv.return_value = []
        mock_invite_user.return_value = None

        response = await invite_users_adapter(request)
        message, status_code = response

        assert status_code == 200
        assert message == "Invitation sent"
        assert mock_invite_user.call_count == 1
        mock_invite_user.assert_called_with(
            unittest.mock.ANY, "user1@example.com", {"fake": "data"}, None
        )


@pytest.mark.asyncio
async def test_invite_users_adapter_invalid_csv_file():
    # Set up test data
    request = unittest.mock.Mock(headers={"Authorization": "fake-jwt-token"})
    request.get_json.return_value = {"csv_file": "fake-invalid-csv-file-contents"}
    # Patch the verify_user, load_emails_from_csv, and invite_user functions
    with unittest.mock.patch(
        "main.verify_user"
    ) as mock_verify_user, unittest.mock.patch(
        "main.load_emails_from_csv"
    ) as mock_load_emails_from_csv:
        mock_verify_user.return_value = {
            "id": 1,
            "email": "user@example.com",
            "app_metadata": {"fake": "data"},
        }
        mock_load_emails_from_csv.return_value = []

        response = await invite_users_adapter(request)
        message, status_code = response

        assert status_code == 400
        assert message == "CSV file not found, invalid or empty"
