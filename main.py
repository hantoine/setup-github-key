import requests
import time
from urllib.parse import parse_qs

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

CLIENT_ID = "036e43bbe946fe74f13f"
DEVICE_CODE_URL = "https://github.com/login/device/code"
TOKEN_URL = "https://github.com/login/oauth/access_token"
SCOPE = "write:public_key"


class GithubSSHKeyCreationFailed(Exception):
    def __init__(self, message: str, http_status_code: int, http_text: str):
        self.message = message
        self.http_status_code = http_status_code
        self.http_text = http_text

    def print(self):
        print(f"{self.message}: {self.http_status_code} ({self.http_text})")


def generate_ssh_key(key_name="id_rsa"):
    key = rsa.generate_private_key(
        backend=default_backend(), public_exponent=65537, key_size=2048
    )
    private_key = key.private_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    with open(f"{key_name}", "wb") as private_file:
        private_file.write(private_key)
    with open(f"{key_name}.pub", "wb") as public_file:
        public_file.write(public_key)
    return public_key.decode("utf-8")


def parse_urlencoded_response(text: str):
    return {k: v[0] for k, v in parse_qs(text).items()}


def initiate_device_flow():
    res = requests.post(
        DEVICE_CODE_URL,
        headers={"Accept": "application/vnd.github.v3+json"},
        data={"client_id": CLIENT_ID, "scope": SCOPE},
    )
    if res.status_code != 200:
        raise GithubSSHKeyCreationFailed(
            "Failed to start device authorization", res.status_code, res.text
        )

    res_dict = res.json()
    device_code = res_dict["device_code"]
    user_code = res_dict["user_code"]
    verification_uri = res_dict["verification_uri"]
    polling_interval = res_dict["interval"]

    print(f"Please go to {verification_uri} and enter the code {user_code}.")

    return device_code, polling_interval


def try_get_access_token(device_code: str) -> str | None:
    res = requests.post(
        TOKEN_URL,
        data={
            "client_id": CLIENT_ID,
            "device_code": device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        },
    )
    if res.status_code != 200:
        raise GithubSSHKeyCreationFailed(
            "Failed to retrieve access token", res.status_code, res.text
        )

    response_dict = parse_urlencoded_response(res.text)
    if "error" in response_dict:
        print(response_dict["error_description"])
        return

    return response_dict["access_token"]


def add_ssh_key(public_key: str, access_token: str) -> None:
    key_response = requests.post(
        url="https://api.github.com/user/keys",
        headers={
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json",
        },
        json={"title": "New SSH Key via Device Flow", "key": public_key},
    )
    if key_response.status_code != 201:
        raise GithubSSHKeyCreationFailed(
            "Failed to add SSH key", key_response.status_code, key_response.text
        )
    print("SSH key added successfully.")


def create_new_github_ssh_key():
    device_code, polling_interval = initiate_device_flow()

    while True:
        time.sleep(polling_interval)
        access_token = try_get_access_token(device_code)
        if access_token is None:
            continue
        public_key = generate_ssh_key()
        add_ssh_key(public_key, access_token)
        break


if __name__ == "__main__":
    try:
        create_new_github_ssh_key()
    except GithubSSHKeyCreationFailed as exc:
        exc.print()
