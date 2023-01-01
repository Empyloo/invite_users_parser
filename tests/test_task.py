import os
import json
import pytest
from unittest import mock
from google.cloud import tasks_v2
from src.task import check_variables, create_task_with_service_account, create_task


def test_check_variables():
    os.environ["PROJECT_ID"] = "test-project"
    os.environ["REGION"] = "us-central1"
    os.environ["INVITE_USER_FUNCTION_URL"] = "https://example.com/invite"
    os.environ[
        "SERVICE_ACCOUNT"
    ] = "test-service-account@test-project.iam.gserviceaccount.com"
    os.environ["QUEUE_NAME"] = "test-queue"
    assert check_variables() == []
    del os.environ["PROJECT_ID"]
    assert check_variables() == ["PROJECT_ID"]


@pytest.fixture
def mock_env():
    """Set up the environment variables required for the test."""
    os.environ["PROJECT_ID"] = "my-project"
    os.environ["REGION"] = "us-central1"
    os.environ["INVITE_USER_FUNCTION_URL"] = "https://example.com/task_handler"
    os.environ["SERVICE_ACCOUNT"] = "service-account@my-project.iam.gserviceaccount.com"
    os.environ["QUEUE_NAME"] = "my-queue"


@pytest.fixture
def mock_client(mock_env):
    """Mock the tasks_v2.CloudTasksClient object."""
    with mock.patch("google.cloud.tasks_v2.CloudTasksClient") as mock_client:
        yield mock_client


@pytest.fixture
def mock_queue_path(mock_client):
    """Mock the queue_path method of the tasks_v2.CloudTasksClient object."""
    mock_queue_path = mock.Mock(
        return_value="projects/my-project/locations/us-central1/queues/my-queue"
    )
    mock_client.return_value.queue_path = mock_queue_path
    yield mock_queue_path


def test_create_task_with_service_account(mock_client, mock_queue_path):
    """Test create_task_with_service_account with a valid payload."""
    payload = '{"email": "user@example.com"}'
    mock_create_task = mock.Mock(return_value=mock.Mock(name="task-123"))
    mock_client.return_value.create_task = mock_create_task
    task = create_task_with_service_account(payload)
    assert task == mock_create_task.return_value
    mock_create_task.assert_called_once_with(
        request={
            "parent": "projects/my-project/locations/us-central1/queues/my-queue",
            "task": {
                "http_request": {
                    "http_method": tasks_v2.HttpMethod.POST,
                    "url": "https://example.com/task_handler",
                    "oidc_token": {
                        "service_account_email": "service-account@my-project.iam.gserviceaccount.com",
                        "audience": "https://example.com/task_handler",
                    },
                    "body": payload.encode(),
                }
            },
        }
    )


def test_create_task_with_service_account_invalid_payload(mock_client, mock_queue_path):
    """Test create_task_with_service_account with an invalid payload."""
    payload = '{"email": "user@example.com"}'
    mock_create_task = mock.Mock(return_value=mock.Mock(name="task-123"))
    mock_client.return_value.create_task = mock_create_task
    task = create_task_with_service_account(payload)
    assert task == mock_create_task.return_value
    mock_create_task.assert_called_once_with(
        request={
            "parent": "projects/my-project/locations/us-central1/queues/my-queue",
            "task": {
                "http_request": {
                    "http_method": tasks_v2.HttpMethod.POST,
                    "url": "https://example.com/task_handler",
                    "oidc_token": {
                        "service_account_email": "service-account@my-project.iam.gserviceaccount.com",
                        "audience": "https://example.com/task_handler",
                    },
                    "body": payload.encode(),
                }
            },
        }
    )


def test_create_task_calls_create_task_with_service_account_with_correct_payload():
    payload = {"email": "user@example.com"}
    expected_payload_str = json.dumps(payload)
    with mock.patch(
        "src.task.create_task_with_service_account"
    ) as create_task_with_service_account_mock:
        create_task(payload)
        create_task_with_service_account_mock.assert_called_once_with(
            payload=expected_payload_str, queue_name=None
        )


def test_create_task_returns_result_of_create_task_with_service_account():
    payload = {"email": "user@example.com"}
    expected_result = {"task_name": "my-task"}
    with mock.patch(
        "src.task.create_task_with_service_account",
        return_value=expected_result,
    ):
        result = create_task(payload)
        assert result == expected_result


def test_create_task_handles_errors_correctly():
    payload = {"email": "user@example.com"}
    with mock.patch(
        "src.task.create_task_with_service_account",
        side_effect=Exception("Something went wrong"),
    ):
        with pytest.raises(Exception) as e:
            create_task(payload)
        assert str(e.value) == "Something went wrong"
