# main.py
"""Cloud Function to invite users
"""

import os
import dotenv
import pandas as pd
import google_crc32c
import functions_framework
from typing import List, Optional, Tuple
from loguru import logger
from google.cloud import secretmanager

from src.task import create_task
from src.user_service import UserService


def get_secret_payload(
    project_id: str, secret_id: str, version_id: str
) -> Optional[str]:
    """
    Access the payload for the given secret version if one exists. The version
    can be a version number as a string (e.g. "5") or an alias (e.g. "latest").
    """
    try:
        client = secretmanager.SecretManagerServiceClient()
        secret_name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
        response = client.access_secret_version(request={"name": secret_name})
        logger.debug("Secret request response successful.")

        crc32c = google_crc32c.Checksum()
        crc32c.update(response.payload.data)

        if response.payload.data_crc32c != int(crc32c.hexdigest(), 16):
            logger.error("Data corruption detected for secret: {}", secret_name)
            logger.error("Error response: {}", response)
            return None

        payload = response.payload.data.decode("UTF-8")
        return payload
    except Exception:
        logger.exception("Error accessing secret payload")
        return None


def load_emails_from_csv(csv_file: str) -> List[str]:
    """Load the emails from the given CSV file and return them as a list."""
    try:
        df = pd.read_csv(csv_file)
        return list(df["emails"])
    except Exception as error:
        logger.exception(error)
        return []


@functions_framework.http
def invite_users(request) -> Tuple[str, int]:
    """The entry point of the Cloud Function. This function is called by the
    Functions Framework to handle incoming requests."""
    if os.path.exists(".env"):
        dotenv.load_dotenv()
    try:
        jwt_token = request.headers.get("Authorization")
        db_url = os.getenv("SUPABASE_URL")
        db_anon_key = os.getenv("SUPABASE_ANON_KEY")
        logger.info("db_url: %s", db_url)
        logger.info("db_anon_key: %s", db_anon_key)
        user_service = UserService(db_url, db_anon_key)
        user = user_service.verify_user(jwt_token)
        if not user:
            logger.error("User not found, unauthorized %s", jwt_token)
            return "Unauthorized", 401
        data = user["app_metadata"]
    except Exception as error:
        logger.error(error)
        return "Failed to verify user", 500

    request_json = request.get_json()
    if not request_json:
        return "Invalid request body", 400

    if "emails" in request_json and "csv_file" in request_json:
        emails = [request_json["emails"]] + load_emails_from_csv(
            request_json["csv_file"]
        )

    elif "csv_file" in request_json:
        emails = load_emails_from_csv(request_json["csv_file"])
        if not emails:
            logger.error("CSV file not found, invalid or empty")
            return "CSV file not found, invalid or empty", 400

    elif "emails" in request_json:
        emails = request_json["emails"]
    else:
        return "No CSV file or emails provided", 400

    queue_name = request_json.get("queue_name")

    emails_with_errors = []
    for email in emails:
        payload = {
            "email": email,
            "company_id": request_json.get("company_id") or data["company_id"],
            "company_name": request_json.get("company_name") or data["company_name"],
            "role": "user",
        }
        task = create_task(payload=payload, queue_name=queue_name)
        if not task:
            emails_with_errors.append(email)

    if len(emails) == len(emails_with_errors):
        logger.error("Failed to invite all users")
        return "Failed to invite all users", 500
    elif emails_with_errors:
        logger.error("Failed to invite some users: {}", emails_with_errors)
        return "Failed to invite some users: {}".format(emails_with_errors), 500
    return "Success", 200
