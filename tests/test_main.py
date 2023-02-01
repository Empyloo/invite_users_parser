from collections import UserString
import pytest
import pandas as pd
from unittest.mock import patch, Mock
from main import (
    verify_user,
    load_emails_from_csv,
    invite_users,
    get_secret_payload,
    check_role,
)


@patch("google.cloud.secretmanager.SecretManagerServiceClient")
def test_get_secret_payload(mock_client):
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
    mock_client.return_value.access_secret_version.side_effect = Exception(
        "Project not found"
    )
    assert get_secret_payload("invalid-project", "my-secret", "5") is None


@patch("main.Client")
def test_verify_user_valid_token(mock_supabase):
    mock_user = {"id": 1, "email": "user@example.com"}
    mock_supabase.auth.api.get_user.return_value = mock_user
    assert verify_user(mock_supabase, "valid-token") == mock_user


@patch("main.Client")
def test_verify_user_exception(mock_supabase):
    mock_supabase.auth.api.get_user.side_effect = Exception("Invalid token")
    assert verify_user(mock_supabase, "invalid-token") is None


def test_load_emails_from_csv_valid_file():
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
    mock_csv = "emails.csv"
    with patch("main.pd.read_csv", side_effect=Exception("Error reading CSV file")):
        emails = load_emails_from_csv(mock_csv)
        assert emails == []


@patch("main.create_client")
@patch("main.verify_user")
@patch("main.load_emails_from_csv")
@patch("main.create_task")
def test_invite_users_valid_request(
    mock_create_task, mock_load_emails_from_csv, mock_verify_user, mock_create_client
):
    mock_request = Mock()
    mock_request.headers = {"Authorization": "valid-token"}
    mock_request.get_json.return_value = {"emails": ["test@email.com"]}
    mock_user = {
        "id": 1,
        "email": "test@email.com",
        "app_metadata": {"company_id": 1, "company_name": "test"},
    }
    mock_verify_user.return_value = mock_user
    mock_create_client.return_value = Mock()
    mock_load_emails_from_csv.return_value = ["test2@email.com"]
    mock_create_task.return_value = True
    assert invite_users(mock_request) == ("Success", 200)


@patch("main.create_client")
@patch("main.verify_user")
@patch("main.load_emails_from_csv")
@patch("main.create_task")
def test_invite_users_unverified_user(
    mock_create_task, mock_load_emails_from_csv, mock_verify_user, mock_create_client
):
    mock_request = Mock()
    mock_request.headers = {"Authorization  ": "invalid"}
    mock_request.get_json.return_value = {"emails": ["invalid@test.com"]}
    mock_user = {
        "id": 1,
        "email": "invalid_admin@test.com",
        "app_metadata": {"company_id": 1, "company_name": "test"},
    }
    mock_verify_user.return_value = None
    mock_create_client.return_value = Mock()
    mock_load_emails_from_csv.return_value = ["invalid2@test.com"]
    assert invite_users(mock_request) == ("Unauthorized", 401)


@patch("main.create_client")
@patch("main.verify_user")
@patch("main.load_emails_from_csv")
@patch("main.create_task")
def test_invite_users_invalid_request_body(
    mock_create_task, mock_load_emails_from_csv, mock_verify_user, mock_create_client
):
    mock_request = Mock()
    mock_request.headers = {"Authorization": "valid-token"}
    mock_request.get_json.return_value = None
    mock_user = {
        "id": 1,
        "email": "test@email.com",
        "app_metadata": {"company_id": 1, "company_name": "test"},
    }
    mock_verify_user.return_value = mock_user
    mock_create_client.return_value = Mock()
    mock_load_emails_from_csv.return_value = ["test_csv@email.com"]
    assert invite_users(mock_request) == ("Invalid request body", 400)


@patch("main.create_client")
@patch("main.verify_user")
@patch("main.load_emails_from_csv")
@patch("main.create_task")
def test_invite_users_no_emails_or_csv_file(
    mock_create_task, mock_load_emails_from_csv, mock_verify_user, mock_create_client
):
    mock_request = Mock()
    mock_request.headers = {"Authorization": "valid-token"}
    mock_request.get_json.return_value = {}
    mock_user = {
        "id": 1,
        "email": "test@email.com",
        "app_metadata": {"company_id": 1, "company_name": "test"},
    }
    mock_verify_user.return_value = mock_user
    mock_create_client.return_value = Mock()
    mock_load_emails_from_csv.return_value = []
    assert invite_users(mock_request) == ("Invalid request body", 400)


@patch("main.create_client")
@patch("main.verify_user")
@patch("main.load_emails_from_csv")
@patch("main.create_task")
def test_invite_users_csv_file_not_found(
    mock_create_task, mock_load_emails_from_csv, mock_verify_user, mock_create_client
):
    mock_request = Mock()
    mock_request.headers = {"Authorization": "valid-token"}
    mock_request.get_json.return_value = {"csv_file": "test.csv"}
    mock_user = {
        "id": 1,
        "email": "test@email.com",
        "app_metadata": {"company_id": 1, "company_name": "test"},
    }
    mock_verify_user.return_value = mock_user
    mock_create_client.return_value = Mock()
    mock_load_emails_from_csv.return_value = []
    assert invite_users(mock_request) == ("CSV file not found, invalid or empty", 400)


@patch("main.create_client")
@patch("main.verify_user")
@patch("main.load_emails_from_csv")
@patch("main.create_task")
def test_invite_users_no_csv_file_or_emails(
    mock_create_task, mock_load_emails_from_csv, mock_verify_user, mock_create_client
):
    mock_request = Mock()
    mock_request.headers = {"Authorization": "valid-token"}
    mock_request.get_json.return_value = {"something": "test"}
    mock_user = {
        "id": 1,
        "email": "test@email.com",
        "app_metadata": {"company_id": 1, "company_name": "test"},
    }
    mock_verify_user.return_value = mock_user
    mock_create_client.return_value = Mock()
    assert invite_users(mock_request) == ("No CSV file or emails provided", 400)


@patch("main.create_client")
@patch("main.verify_user")
@patch("main.load_emails_from_csv")
@patch("main.create_task")
def test_invite_users_create_task_called_with_correct_payload(
    mock_create_task, mock_load_emails_from_csv, mock_verify_user, mock_create_client
):
    mock_request = Mock()
    mock_request.headers = {"Authorization": "valid-token"}
    mock_request.get_json.return_value = {"emails": ["invited@email.com"]}
    mock_user = {
        "id": 1,
        "email": "test@user.com",
        "app_metadata": {"company_id": 1, "company_name": "test"},
    }
    mock_verify_user.return_value = mock_user
    mock_create_client.return_value = Mock()
    mock_load_emails_from_csv.return_value = []
    invite_users(mock_request)
    assert mock_create_task.call_count == 1
    assert mock_create_task.call_args.kwargs == {
        "payload": {
            "email": "invited@email.com",
            "company_id": 1,
            "company_name": "test",
            "role": "user",
        },
        "queue_name": None,
    }


@patch("main.create_client")
@patch("main.verify_user")
@patch("main.load_emails_from_csv")
@patch("main.create_task")
def test_invite_users_failed_to_invite_all_users(
    mock_create_task, mock_load_emails_from_csv, mock_verify_user, mock_create_client
):
    mock_request = Mock()
    mock_request.headers = {"Authorization": "valid-token"}
    mock_request.get_json.return_value = {
        "emails": ["test@email.com", "test2@email.com"]
    }
    mock_user = {
        "id": 1,
        "email": "test_admin@email.com",
        "app_metadata": {"company_id": 1, "company_name": "test"},
    }
    mock_verify_user.return_value = mock_user
    mock_create_client.return_value = Mock()
    mock_load_emails_from_csv.return_value = []
    mock_create_task.return_value = False
    assert invite_users(mock_request) == ("Failed to invite all users", 500)


@patch("main.create_client")
@patch("main.verify_user")
@patch("main.load_emails_from_csv")
@patch("main.create_task")
def test_invite_users_failed_to_invite_some_users(
    mock_create_task, mock_load_emails_from_csv, mock_verify_user, mock_create_client
):
    mock_request = Mock()
    mock_request.headers = {"Authorization": "valid-token"}
    mock_request.get_json.return_value = {
        "emails": ["test@email.com", "test2@email.com"]
    }
    mock_user = {
        "id": 1,
        "email": "test_admin@email.com",
        "app_metadata": {"company_id": 1, "company_name": "test"},
    }
    mock_verify_user.return_value = mock_user
    mock_create_client.return_value = Mock()
    mock_load_emails_from_csv.return_value = []
    mock_create_task.side_effect = [True, False]
    assert invite_users(mock_request) == (
        "Failed to invite some users: ['test2@email.com']",
        500,
    )

def test_check_role():
    assert check_role("user") == True
    assert check_role("admin") == True
    assert check_role("invalid_role") == False

@patch("main.get_secret_payload")
@patch("main.create_client")
@patch("main.verify_user")
@patch("main.load_emails_from_csv")
@patch("main.create_task")
def test_get_secret_payload_gets_called(
    mock_create_task,
    mock_load_emails_from_csv,
    mock_verify_user,
    mock_create_client,
    mock_get_secret_payload,
):
    mock_request = Mock()
    mock_request.headers = {"Authorization": "valid-token"}
    mock_request.get_json.return_value = {"emails": ["test@email.com"]}
    mock_user = {
        "id": 1,
        "email": "test@email.com",
        "app_metadata": {"company_id": 1, "company_name": "test"},
    }
    mock_verify_user.return_value = mock_user
    mock_create_client.return_value = Mock()
    mock_load_emails_from_csv.return_value = ["test2@email.com"]
    mock_create_task.return_value = True
    invite_users(mock_request)
    mock_get_secret_payload.assert_called_once()