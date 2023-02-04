import os
import json
from typing import List
from loguru import logger
from google.cloud import tasks_v2
from tenacity import retry, stop_after_attempt, wait_exponential


def check_variables() -> List[str]:
    """Check that all required environment variables are set."""
    variables = [
        "PROJECT_ID",
        "REGION",
        "INVITE_USER_FUNCTION_URL",
        "SERVICE_ACCOUNT",
        "QUEUE_NAME",
    ]
    undefined_variables = []
    for var in variables:
        if not os.getenv(var):
            undefined_variables.append(var)
    return undefined_variables


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
def create_task_with_service_account(
    payload: str, queue_name: str = None
) -> tasks_v2.types.task.Task:
    """Create a task for a given queue with an arbitrary payload.

    Args:
        payload: The task HTTP request body.
        queue_name: The queue name. If None, the default queue is used.
    Returns:
        The created task.
    """
    try:
        project = os.getenv("PROJECT_ID")
        location = os.getenv("REGION")
        url = os.getenv("INVITE_USER_FUNCTION_URL")
        audience = os.getenv("INVITE_USER_FUNCTION_URL")
        service_account_email = os.getenv("SERVICE_ACCOUNT")
        queue = os.getenv("QUEUE_NAME")

        missing_env_variable = check_variables()
        if missing_env_variable:
            logger.error("Missing environment variables %s" % missing_env_variable)
            return None

        client = tasks_v2.CloudTasksClient()
        # Construct the fully qualified queue name.
        parent = client.queue_path(project, location, queue)

        # Construct the request body.
        task = {
            "http_request": {
                "http_method": tasks_v2.HttpMethod.POST,
                "url": url,
                "oidc_token": {
                    "service_account_email": service_account_email,
                    "audience": audience,
                },
            }
        }

        if payload is not None:
            # The API expects a payload of type bytes.
            converted_payload = payload.encode()

            # Add the payload to the request.
            task["http_request"]["body"] = converted_payload

        # Use the client to build and send the task.
        response = client.create_task(request={"parent": parent, "task": task})

        logger.info("Created task {}".format(response.name))
        return response
    except Exception as error:
        logger.error(
            "Error creating task for queue '{}' with payload '{}': {}",
            queue_name,
            payload,
            error,
        )
        raise


def create_task(payload: dict, queue_name: str = None) -> tasks_v2.types.task.Task:
    """Calls create_task_with_service_account with a payload

    Args:
        payload: The task HTTP request body.
        queue_name: The queue name. If None, the default queue is used.
    Returns:
        The created task.
    """
    payload_str = json.dumps(payload)
    return create_task_with_service_account(payload=payload_str, queue_name=queue_name)
