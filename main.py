import re
import socket
import requests
import time
import subprocess
import pathlib

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


def generate_ssh_key(key_filename="id_rsa") -> str:
    assert re.match(r"^[a-zA-Z_-]+$", key_filename)
    key_path = pathlib.Path.home() / ".ssh" / key_filename
    subprocess.check_call(
        [
            "/usr/bin/ssh-keygen",
            "-q",
            *("-t", "rsa"),
            *("-b", "4096"),
            *("-N", "''"),
            *("-f", key_path),
        ]
    )
    with key_path.with_suffix(".pub").open() as public_file:
        return public_file.read()


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
        headers={"Accept": "application/vnd.github.v3+json"},
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

    response_dict = res.json()
    if "error" in response_dict:
        if response_dict["error"] != "authorization_pending":
            raise GithubSSHKeyCreationFailed(
                "Failed to get access token", res.status_code, res.text
            )
        else:
            return None

    print("Authorization request completed")
    return response_dict["access_token"]


def add_new_ssh_key(access_token: str, key_title: str, key_filename: str) -> None:
    public_key = generate_ssh_key(key_filename)
    key_response = requests.post(
        url="https://api.github.com/user/keys",
        headers={
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json",
        },
        json={"title": key_title, "key": public_key},
    )
    if key_response.status_code != 201:
        raise GithubSSHKeyCreationFailed(
            "Failed to add SSH key", key_response.status_code, key_response.text
        )
    print("SSH key added successfully.")

def configure_ssh_key(key_filename: str):
    ssh_config_path = pathlib.Path.home() / ".ssh/config"
    with ssh_config_path.open("a") as ssh_config_file:
        ssh_config_file.write(
            "Host github.com\n"
            f"  IdentityFile ~/.ssh/{key_filename}\n"
            "  IdentitiesOnly yes\n"
        )


def create_new_github_ssh_key(key_title: str, key_filename: str):
    device_code, polling_interval = initiate_device_flow()
    print("Waiting for the authorization request to complete...")
    while True:
        time.sleep(polling_interval)
        access_token = try_get_access_token(device_code)
        if access_token is not None:
            break
    add_new_ssh_key(access_token, key_title, key_filename)
    configure_ssh_key(key_filename)


def get_ssh_key_title_from_hostname():
    hostname = socket.gethostname().split(".")[0]
    return "SSH Key " + hostname.replace("-", " ")


if __name__ == "__main__":
    try:
        ssh_key_title = get_ssh_key_title_from_hostname()
        create_new_github_ssh_key(ssh_key_title, "github_key")
    except GithubSSHKeyCreationFailed as exc:
        exc.print()
    else:
        # Authorizing an SSH key cannot be done though the API at the moment, see:
        #   https://stackoverflow.com/q/60104002
        print(
            'Go to https://github.com/settings/ssh, click on "Configure SSO" for the '
            f'SSH key named "{ssh_key_title}", and authorize it'
        )
