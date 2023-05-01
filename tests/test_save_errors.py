import pytest
from unittest.mock import Mock

from src.save_errors import save_errors


def test_save_errors_success():
    # Create a mock RestService object
    rest_service = Mock()
    rest_service.create.return_value = "success"

    # Call the save_errors function
    response = save_errors(
        rest_service=rest_service,
        table="failed_invites",
        data={"email": "test@example.com", "payload": {"error": "Test User"}},
        error="Test error",
    )

    # Assert that the create method was called with the correct arguments
    rest_service.create.assert_called_with(
        table="failed_invites",
        data={
            "email": "test@example.com",
            "payload": {"payload": {"error": "Test User"}},
            "reason": "Test error",
        },
    )

    # Assert that the response is correct
    assert response == "success"


def test_save_errors_exception():
    # Create a mock RestService object that raises an exception
    rest_service = Mock()
    rest_service.create.side_effect = Exception("Test error")

    # Call the save_errors function
    response = save_errors(
        rest_service=rest_service,
        table="failed_invites",
        data={"email": "test@example.com", "payload": {"error": "Test User"}},
        error="Test error",
    )

    # Assert that the create method was called with the correct arguments
    rest_service.create.assert_called_with(
        table="failed_invites",
        data={
            "email": "test@example.com",
            "payload": {"payload": {"error": "Test User"}},
            "reason": "Test error",
        },
    )

    # Assert that the response is None
    assert response is None