import json
import os
import urllib.parse
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler

import requests
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:5000")

AUTHORIZE_URL = "https://api-identity.bqecore.com/idp/connect/authorize"
TOKEN_URL = "https://api-identity.bqecore.com/idp/connect/token"
SCOPE = "readwrite:core offline_access openid"
AUTH_RESPONSE_FILE = "auth_response.json"


class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """HTTP request handler that captures the OAuth redirect and extracts the authorization code."""

    def do_GET(self):
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)

        if "code" in params:
            self.server.auth_code = params["code"][0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body><h1>Authorization successful!</h1>"
                b"<p>You can close this window.</p></body></html>"
            )
        else:
            self.server.auth_code = None
            error = params.get("error", ["unknown"])[0]
            self.send_response(400)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                f"<html><body><h1>Authorization failed</h1>"
                f"<p>Error: {error}</p></body></html>".encode()
            )

    def log_message(self, format, *args):
        # Suppress default logging output
        pass


def get_authorization_code():
    """Open a browser to the BQE authorization page and start a local server to capture the redirect."""
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
    }
    auth_url = f"{AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

    server = HTTPServer(("localhost", 5000), OAuthCallbackHandler)
    server.auth_code = None

    print("Opening browser for BQE CORE authorization...")
    webbrowser.open(auth_url)

    print("Waiting for authorization callback on http://localhost:5000 ...")
    server.handle_request()
    server.server_close()

    if server.auth_code is None:
        raise RuntimeError("Failed to obtain authorization code.")

    print("Authorization code received.")
    return server.auth_code


def exchange_code_for_tokens(code):
    """Exchange the authorization code for access and refresh tokens."""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }

    response = requests.post(TOKEN_URL, data=data)
    response.raise_for_status()
    return response.json()


def save_auth_response(token_data):
    """Save access_token, refresh_token, and base_url to auth_response.json."""
    auth_data = {
        "access_token": token_data["access_token"],
        "refresh_token": token_data["refresh_token"],
        "base_url": token_data["base_url"],
    }
    with open(AUTH_RESPONSE_FILE, "w") as f:
        json.dump(auth_data, f, indent=2)
    print(f"Auth response saved to {AUTH_RESPONSE_FILE}")


def load_auth_response():
    """Load the saved auth response from disk."""
    with open(AUTH_RESPONSE_FILE, "r") as f:
        return json.load(f)


def refresh_access_token():
    """Use the saved refresh token to obtain a new access token."""
    auth_data = load_auth_response()

    data = {
        "grant_type": "refresh_token",
        "refresh_token": auth_data["refresh_token"],
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }

    response = requests.post(TOKEN_URL, data=data)
    response.raise_for_status()
    token_data = response.json()

    auth_data["access_token"] = token_data["access_token"]
    if "refresh_token" in token_data:
        auth_data["refresh_token"] = token_data["refresh_token"]

    with open(AUTH_RESPONSE_FILE, "w") as f:
        json.dump(auth_data, f, indent=2)

    print("Access token refreshed and saved.")
    return auth_data["access_token"]


def get_time_entries():
    """Fetch time entries from the BQE CORE API and print the results."""
    auth_data = load_auth_response()
    base_url = auth_data["base_url"]
    access_token = auth_data["access_token"]

    headers = {
        "Authorization": f"Bearer {access_token}",
    }

    url = f"{base_url}/v1/timeentry"
    response = requests.get(url, headers=headers)
    response.raise_for_status()

    data = response.json()
    print(json.dumps(data, indent=2))
    return data


if __name__ == "__main__":
    code = get_authorization_code()
    token_data = exchange_code_for_tokens(code)
    save_auth_response(token_data)
    print("\nFetching time entries...")
    get_time_entries()
