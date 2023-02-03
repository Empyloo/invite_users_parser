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
from src.user_service import AdminUserService


def extract_token_from_header(headers) -> Optional[str]:
    authorization_header = headers.get("Authorization")
    if not authorization_header:
        logger.error("No Authorization header found: %s" % headers)
        return None

    header_parts = authorization_header.split(" ")
    if len(header_parts) != 2 or header_parts[0] != "Bearer":
        logger.error("Invalid Authorization header, more than 2 parts: %s" % headers)
        return None

    return header_parts[1]


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


def check_email(email: str) -> bool:
    """Check if the given email is an Empylo email (ends with @empylo.com).
    Returns:
        bool: True if the email it is an Empylo email, False otherwise.
    """
    return email.endswith("@empylo.com")


@functions_framework.http
def invite_users(request) -> Tuple[str, int]:
    """The entry point of the Cloud Function. This function is called by the
    Functions Framework to handle incoming requests."""
    if os.path.exists(".env"):
        dotenv.load_dotenv()
    try:
        service_key = get_secret_payload(
            os.getenv("PROJECT_ID"),
            os.getenv("SUPABASE_SERVICE_ROLE_SECRET_ID"),
            os.getenv("VERSION_ID"),
        )
    except Exception as error:
        logger.error("Failed to get Supabase key: %s", error)
        return "Failed to get Supabase key", 500
    try:
        jwt_token = extract_token_from_header(request.headers)
        db_url = os.getenv("SUPABASE_URL")
        db_anon_key = os.getenv("SUPABASE_ANON_KEY")
        user_service = AdminUserService(db_url, db_anon_key, service_key)
        user = user_service.verify_user(jwt_token)
        if "error" in user:
            logger.error("%s %s" % (user["error"], jwt_token))
            return user["error"], 401
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
