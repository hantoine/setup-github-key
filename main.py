from flask import Flask, request, redirect
import requests
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

CLIENT_ID = "your_github_client_id"
CLIENT_SECRET = "your_github_client_secret"
REDIRECT_URI = "http://localhost:5000/callback"

def generate_ssh_key(key_name="id_rsa"):
    key = rsa.generate_private_key(
        backend=default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    with open(f"{key_name}", "wb") as private_file:
        private_file.write(private_key)
    with open(f"{key_name}.pub", "wb") as public_file:
        public_file.write(public_key)
    return public_key.decode('utf-8')

@app.route('/')
def home():
    return '<a href="https://github.com/login/oauth/authorize?client_id={}&scope=write:public_key">Authorize with GitHub</a>'.format(CLIENT_ID)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if code:
        data = {
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'code': code,
            'redirect_uri': REDIRECT_URI
        }
        headers = {'Accept': 'application/json'}
        r = requests.post('https://github.com/login/oauth/access_token', data=data, headers=headers)
        access_token = r.json().get('access_token')
        if access_token:
            public_key = generate_ssh_key()
            url = "https://api.github.com/user/keys"
            headers = {
                "Authorization": f"token {access_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            payload = {
                "title": "New SSH Key",
                "key": public_key
            }
            response = requests.post(url, headers=headers, json=payload)
            if response.status_code == 201:
                return "SSH key added successfully."
            else:
                return "Failed to add SSH key. Response: {}".format(response.text)
        return "Failed to get access token."
    return "No code provided."

if __name__ == "__main__":
    app.run(debug=True)
