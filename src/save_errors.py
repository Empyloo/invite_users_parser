# Path: src/save_errors.py
from typing import Dict, Optional
import httpx
from loguru import logger

from src.rest_service import RestService


def create_error_payload(
    payload: Dict[str, str], error: Exception | str
) -> Dict[str, str]:
    """Create a new dictionary containing the payload and the error message.
    Args:
        payload: A dictionary containing the payload.
        error: The exception object or error message.
    Returns:
        A dictionary containing the payload and the error message.
    """
    data = {}
    data["email"] = payload["email"]
    payload.pop("email")
    data["payload"] = payload
    data["reason"] = str(error)
    return data


def save_errors(
    rest_service: RestService,
    table: str,
    data: Dict[str, str],
    error: Exception | str,
) -> Optional[httpx.Response]:
    """Create a new failed invite record in the specified table.
    Args:
        rest_service: An instance of the RestService class.
        table: The name of the table.
        data: A dictionary containing the data to be inserted.
        error: The exception object or error message.
    Returns:
        A response object containing the result of the operation, or None if an exception is raised.
    """
    try:
        data = create_error_payload(payload=data, error=error)
        response = rest_service.create(table=table, data=data)
        return response
    except Exception as error:
        logger.error("Error saving failed invite: {}", error)
        return None


if __name__ == "__main__":
    import os
    from exp_invite import base_url, anon_key, service_role_key

    SUPABASE_URL = base_url or os.getenv("PROD_SUPABASE_URL")
    SUPABASE_KEY = service_role_key or os.getenv("PROD_SUPABASE_SERVICE_ROLE_KEY")

    email = "test@email.com"
    payload = {
        "email": email,
        "payload": {"error": "Test User"},
        "reason": "Test User",
    }
    try:
        rest_service = RestService(
            base_url=SUPABASE_URL, api_key=anon_key, service_key=SUPABASE_KEY
        )
        response = save_errors(
            rest_service=rest_service,
            table="failed_invites",
            data=payload,
            error="Test",
        )
        print(response.status_code)
    except Exception as error:
        print(error)
