# src/user_service.py
import jwt
import requests
import datetime


class AdminUserService:
    def __init__(self, base_url: str, anon_key: str, service_key: str):
        self.base_url = base_url
        self.anon_key = anon_key
        self.service_key = service_key
        self.headers = {
            "apikey": self.anon_key,
            "X-Client-Info": "supabase-py/0.01",
            "Authorization": f"Bearer {self.service_key}",
        }

    def get_user_by_id(self, user_id: str):
        """Get a user by their user_id"""
        response = requests.get(
            f"{self.base_url}/auth/v1/admin/users/{user_id}",
            headers=self.headers,
            timeout=5,
        )
        return response

    def generate_link(self):
        """Generate a link to invite a user to your project."""
        response = requests.post(
            f"{self.base_url}/auth/v1/admin/generate_link",
            headers=self.headers,
            timeout=5,
        )
        return response

    def delete_user(self, user_id: str):
        """Delete a user by their user_id"""
        response = requests.delete(
            f"{self.base_url}/auth/v1/admin/users/{user_id}",
            headers=self.headers,
            timeout=5,
        )
        return response

    @staticmethod
    def is_jwt_valid(jwt_token: str) -> dict:
        """Checks if the JWT token is currently valid.
        If the token is  valid the decoded JWT is returned.
        In any other case, a dictionary with the error message is returned.

        Returns:
            Dict[str, str]:
        """
        try:
            decoded_jwt = jwt.decode(jwt_token, options={"verify_signature": False})
        except (jwt.DecodeError, jwt.ExpiredSignatureError):
            return {"error": "Invalid JWT"}

        current_time = datetime.datetime.utcnow()
        exp = decoded_jwt.get("exp")
        if exp is None:
            return {"error": "No expiration time in JWT"}

        exp_timestamp = datetime.datetime.utcfromtimestamp(exp)
        if exp_timestamp > current_time:
            return decoded_jwt
        else:
            return {"error": "Expired JWT"}

    def verify_user(self, jwt_token: str) -> dict:
        """Verifies a user based on the user `id` and JWT token.

        Returns:
            dict:
                A dictionary with the user metadata if the user is a super admin.
        """
        jwt_valid = self.is_jwt_valid(jwt_token)
        if "error" in jwt_valid:
            return jwt_valid

        user_id = jwt_valid.get("sub")
        response = self.get_user_by_id(user_id)
        if response.status_code != 200:
            return {"error": "User id does not exis."}

        user = response.json()
        if user.get("app_metadata") is None:
            return {"error": "User does not have app metadata"}

        user_metadata = user.get("app_metadata")
        if user_metadata.get("role") != "super_admin":
            return {"error": "User is not a super admin"}
        return user_metadata
