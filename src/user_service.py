import requests
from typing import Dict, Any

class UserService:
    def __init__(self, base_url: str, anon_key: str):
        self.base_url = base_url
        self.anon_key = anon_key
        self.headers = {"apikey": self.anon_key}
    
    def verify_user(self, jwt_token: str):
        self.headers["Authorization"] = f"Bearer {jwt_token}"
        response = requests.get(f"{self.base_url}/auth/v1/user", headers=self.headers, timeout=5)
        if response.status_code == 200:
            return response.json()
        return None
        
    def get_user_details(self, jwt_token: str):
        self.headers["Authorization"] = f"Bearer {jwt_token}"
        response = requests.get(f"{self.base_url}/auth/v1/user/details", headers=self.headers, timeout=5)
        if response.status_code == 200:
            return response.json()
        return None
    
    def update_user_details(self, jwt_token: str, payload: Dict[str, Any]):
        self.headers["Authorization"] = f"Bearer {jwt_token}"
        response = requests.patch(f"{self.base_url}/auth/v1/user/details", headers=self.headers, json=payload, timeout=5)
        if response.status_code == 200:
            return response.json()
        return None
