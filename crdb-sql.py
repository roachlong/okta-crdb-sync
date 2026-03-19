import http.server
import socketserver
import subprocess
import requests
import urllib.parse
import os
import subprocess
import json
import time
import argparse
from dotenv import load_dotenv

parser = argparse.ArgumentParser()
parser.add_argument("--env", default="dev", help="Environment (dev, prod, etc)")
args = parser.parse_args()

env = args.env or os.environ.get("CRDB_ENV", "dev")
env_file = f".env.{env}"
print(f"🔧 Loading config from {env_file}")
load_dotenv(env_file)

required = ["OKTA_DOMAIN", "CLIENT_ID", "CLIENT_SECRET"]
for var in required:
    if not os.getenv(var):
        raise Exception(f"Missing required config: {var}")

OKTA_DOMAIN = os.environ["OKTA_DOMAIN"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
CRDB_HOST = os.environ.get("CRDB_HOST", "localhost")
CRDB_PORT = os.environ.get("CRDB_PORT", "26257")
CRDB_DB = os.environ.get("CRDB_DB", "defaultdb")
CRDB_CERTS_DIR = os.environ.get("CRDB_CERTS_DIR", "./certs")

PORT = 8765
REDIRECT_URI = f"http://localhost:{PORT}/callback"
TOKEN_CACHE = os.path.expanduser("~/.crdb_token.json")

auth_code = None

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        global auth_code
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if "code" in params:
            auth_code = params["code"][0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Login successful. You can close this window.")
        else:
            self.send_response(400)
            self.end_headers()

def get_cached_token():
    if not os.path.exists(TOKEN_CACHE):
        return None

    with open(TOKEN_CACHE) as f:
        data = json.load(f)

    if data["exp"] > time.time():
        return data["id_token"]

    return None

def save_token(id_token, exp):
    with open(TOKEN_CACHE, "w") as f:
        json.dump({"id_token": id_token, "exp": exp}, f)

def decode_payload(token):
    payload = token.split(".")[1] + "=="
    return json.loads(
        __import__("base64").urlsafe_b64decode(payload.encode())
    )

def exchange_code(code):
    resp = requests.post(
        f"{OKTA_DOMAIN}/v1/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
        auth=(CLIENT_ID, CLIENT_SECRET),
    )
    resp.raise_for_status()
    data = resp.json()

    id_token = data["id_token"]

    # decode payload
    payload = decode_payload(id_token)
    email = payload["email"]
    user = email.split("@")[0]

    save_token(id_token, payload["exp"])

    return id_token, user

def login():
    global auth_code

    with socketserver.TCPServer(("localhost", PORT), Handler) as httpd:
        url = (
            f"{OKTA_DOMAIN}/v1/authorize?"
            f"client_id={CLIENT_ID}"
            f"&response_type=code"
            f"&scope=openid%20email%20groups"
            f"&redirect_uri={urllib.parse.quote(REDIRECT_URI)}"
            f"&state=abc&nonce=xyz"
        )

        subprocess.run([
            "open", "-na", "Google Chrome",
            "--args", "--incognito", url
        ])

        while auth_code is None:
            httpd.handle_request()

    return exchange_code(auth_code)

def main():
    token = get_cached_token()
    user = None

    if not token:
        print("🔐 Logging in via Okta...")
        token, user = login()
    else:
        # decode cached token to get user
        payload = decode_payload(token)
        user = payload["email"].split("@")[0]

    conn = (
        f"postgresql://{user}:{token}@{CRDB_HOST}:{CRDB_PORT}/{CRDB_DB}"
        f"?sslmode=verify-full&options=--crdb:jwt_auth_enabled=true"
    )

    subprocess.run([
        "cockroach", "sql",
        "--certs-dir", CRDB_CERTS_DIR,
        "--url", conn
    ])

if __name__ == "__main__":
    main()
