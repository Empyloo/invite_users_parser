# main.py
"""Cloud Function to invite users
This script imports data classes, loguru, pandas, function_framework, 
google_crc32c, and superbase, .Then it defines a function called verify user,
which takes in a UWT token and  makes a request to superbase.auth.api.getUser
and if a user is returned, then return the user and if the user is not returned,
return none and log all of those operations using logger.logger.
I also defined another function that takes in  a string that defines the
location of a CSV file, then it uses pandas.read_csv to import or load the CSV
file into memory and returns a list of the emails and  in the emails column
and then the invite user function, which is the entry point of the Cloud Function.
And this is taken by a functions framework as such. 
This one calls verify user first and if the user is verified, it will look in
the request body for either location of the CSV file or a list of emails.
In the JWT token, there should be a company ID  in the app uses metadata so that
company ID along with the email is used to invite a user. It's necessary because
each user has to belong to a company.
"""

import os
import dotenv
import asyncio
import pandas as pd
import google_crc32c
import functions_framework
from typing import List, Optional
from loguru import logger
from google.cloud import secretmanager
from supabase import create_client, Client
from tenacity import retry, stop_after_attempt, wait_exponential
from gotrue.types import User


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


def verify_user(supabase_client: Client, jwt_token: str) -> Optional[dict]:
    """Verify the given JWT token with the supabase auth service and return the
    user if it is valid."""
    try:
        user = supabase_client.auth.api.get_user(jwt_token)
        if user:
            return user
        else:
            return None
    except Exception as error:
        logger.exception(error)
        return None


def load_emails_from_csv(csv_file: str) -> List[str]:
    """Load the emails from the given CSV file and return them as a list."""
    try:
        df = pd.read_csv(csv_file)
        return list(df["emails"])
    except Exception as error:
        logger.exception(error)
        return []


@retry(reraise=True, stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=60))
async def invite_user(supabase_client: Client, email: str, data: dict, role: str = None) -> Optional[str]:
    """Invite the given user to join the given company and return the email if it fails."""
    if role:
        data["role"] = role
    else:
        data["role"] = "user"
    try:
        await supabase_client.auth.api.invite_user_by_email(email=email, data=data)
    except Exception as error:
        logger.exception("Error inviting user %s: %s", email, error)
        return email


@functions_framework.http
def invite_users(request):
    """The entry point of the Cloud Function. This function is called by the
    Functions Framework to handle incoming requests."""
    jwt_token = request.headers.get("Authorization")
    if os.path.exists(".env"):
        dotenv.load_dotenv()

    supabase: Client = create_client(
        os.environ.get("SUPABASE_URL"), os.environ.get("SUPABASE_SERVICE_KEY")
    )
    user = verify_user(supabase_client=supabase, jwt_token=jwt_token)
    if not user:
        return "Unauthorized", 401

    data = user["app_metadata"]

    request_json = request.get_json()
    if not request_json:
        # log invalid attempt
        return "Invalid request body", 400

    if "csv_file" in request_json:
        try:
            emails = load_emails_from_csv(request_json["csv_file"])
        except FileNotFoundError as error:
            logger.error(error)
            return "CSV file not found", 400
    elif "emails" in request_json:
        emails = request_json["emails"]
    else:
        return "No CSV file or emails provided", 400

    role = request_json.get("role")
    try:
        # save the emmails that error.
        asyncio.gather(
            *[
                invite_user(supabase_client=supabase, email=email, data=data, role=role)
                for email in emails
            ]
        )
    except Exception as error:
        logger.error(error)
        return "Failed to invite users", 500
    else:
        return "Invitation sent", 200
