"""Example Flask app that uses FybeAuth OAuth2 for authentication.

Configuration via environment variables or direct assignment:
  OAUTH_CLIENT_ID     – client_id registered with FybeAuth
  OAUTH_CLIENT_SECRET – client_secret registered with FybeAuth
  OAUTH_SERVER_URL    – base URL of the FybeAuth server (default: http://localhost:5000)
  SECRET_KEY          – Flask session secret
  PORT                – port this app listens on (default: 5001)
"""
import os
import secrets

import requests
from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

OAUTH_SERVER = os.environ.get("OAUTH_SERVER_URL", "http://localhost:5000")
CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:5001/callback")

AUTHORIZE_URL = f"{OAUTH_SERVER}/oauth/authorize"
TOKEN_URL = f"{OAUTH_SERVER}/oauth/token"
USERINFO_URL = f"{OAUTH_SERVER}/api/userinfo"


@app.route("/")
def index():
    user = session.get("user")
    return render_template("index.html", user=user)


@app.route("/login")
def login():
    """Redirect the browser to the OAuth2 authorization endpoint."""
    state = secrets.token_urlsafe(16)
    session["oauth_state"] = state
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "profile",
        "state": state,
    }
    from urllib.parse import urlencode
    return redirect(f"{AUTHORIZE_URL}?{urlencode(params)}")


@app.route("/callback")
def callback():
    """Handle the authorization code callback from the OAuth2 server."""
    error = request.args.get("error")
    if error:
        return render_template("index.html", error=f"OAuth error: {error}")

    state = request.args.get("state")
    if state != session.pop("oauth_state", None):
        return render_template("index.html", error="Invalid state parameter."), 400

    code = request.args.get("code")
    # Exchange authorization code for tokens
    token_response = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
        auth=(CLIENT_ID, CLIENT_SECRET),
    )
    if not token_response.ok:
        return render_template(
            "index.html",
            error=f"Token exchange failed: {token_response.text}",
        )

    token_data = token_response.json()
    session["access_token"] = token_data["access_token"]
    session["refresh_token"] = token_data.get("refresh_token")

    # Fetch user info
    userinfo_response = requests.get(
        USERINFO_URL,
        headers={"Authorization": f"Bearer {session['access_token']}"},
    )
    if userinfo_response.ok:
        session["user"] = userinfo_response.json()

    return redirect(url_for("profile"))


@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("profile.html", user=session["user"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(debug=True, port=port)
