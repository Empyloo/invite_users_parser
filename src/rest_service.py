# Path: src.rest_service.py
import httpx
from typing import Dict, Optional
from tenacity import retry, wait_exponential, stop_after_attempt


class RestService:
    def __init__(self, base_url: str, api_key: str, service_key: str):
        self.base_url = base_url
        self.api_key = api_key
        self.headers = {
            "apikey": api_key,
            "Authorization": f"Bearer {service_key}",
            "Content-Type": "application/json",
        }

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30), stop=stop_after_attempt(5)
    )
    def create(self, table: str, data: Dict[str, str]) -> httpx.Response:
        """Create a new record in the specified table.
        Args:
            table: The name of the table.
            data: A dictionary containing the data to be inserted.
        Returns:
            A response object containing the result of the operation.
        """
        return httpx.post(
            f"{self.base_url}/rest/v1/{table}",
            headers=self.headers,
            json=data,
        )


if __name__ == "__main__":
    # from dotenv import load_dotenv
    import os
    from exp_invite import base_url, anon_key, service_role_key

    # load_dotenv()

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
        response = rest_service.create(table="failed_invites", data=payload)
        print(response.json())
    except Exception as error:
        print(error)
