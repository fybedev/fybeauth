"""Tests for the FybeAuth OAuth2 server."""
import json
import pytest
from base64 import b64encode

from oauth_server.app import create_app
from oauth_server.models import db, User, OAuth2Client


@pytest.fixture
def app():
    application = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SECRET_KEY": "test-secret",
            "SERVER_NAME": "localhost",
        }
    )
    yield application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()


# --------------------------------------------------------------------------- helpers

def _register_user(client, username="alice", password="password"):
    return client.post(
        "/register",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def _login_user(client, username="alice", password="password"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def _create_oauth_client(app, user_id, redirect_uri="http://localhost:5001/callback"):
    with app.app_context():
        import secrets
        oauth_client = OAuth2Client(user_id=user_id)
        oauth_client.set_client_metadata(
            {
                "client_name": "TestApp",
                "client_uri": "http://localhost:5001",
                "redirect_uris": [redirect_uri],
                "scope": "profile",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "client_secret_basic",
            }
        )
        oauth_client.client_id = secrets.token_urlsafe(16)
        oauth_client.client_secret = secrets.token_urlsafe(32)
        db.session.add(oauth_client)
        db.session.commit()
        return oauth_client.client_id, oauth_client.client_secret


# --------------------------------------------------------------------------- tests

class TestUserAuth:
    def test_register_success(self, client):
        resp = _register_user(client)
        assert resp.status_code == 200

    def test_register_duplicate(self, client):
        _register_user(client)
        resp = _register_user(client)
        assert b"Username already taken" in resp.data

    def test_login_success(self, client):
        _register_user(client)
        with client.session_transaction() as sess:
            sess.clear()
        resp = _login_user(client)
        assert resp.status_code == 200

    def test_login_invalid_credentials(self, client):
        _register_user(client)
        resp = client.post(
            "/login",
            data={"username": "alice", "password": "wrong"},
            follow_redirects=True,
        )
        assert b"Invalid credentials" in resp.data

    def test_logout(self, client):
        _register_user(client)
        resp = client.get("/logout", follow_redirects=True)
        assert resp.status_code == 200


class TestOAuthFlow:
    def test_authorize_redirects_to_login(self, client):
        resp = client.get(
            "/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost:5001/callback&scope=profile"
        )
        assert resp.status_code in (302, 301)
        assert "/login" in resp.headers["Location"]

    def test_full_authorization_code_flow(self, app, client):
        # 1. Register user
        _register_user(client, "bob", "secret")

        with app.app_context():
            user = User.query.filter_by(username="bob").first()
            user_id = user.id

        client_id, client_secret = _create_oauth_client(app, user_id)

        # 2. Login
        _login_user(client, "bob", "secret")

        # 3. GET /oauth/authorize – show consent screen
        resp = client.get(
            f"/oauth/authorize?response_type=code&client_id={client_id}"
            f"&redirect_uri=http://localhost:5001/callback&scope=profile"
        )
        assert resp.status_code == 200
        assert b"Authorize Application" in resp.data

        # 4. POST /oauth/authorize – grant access
        resp = client.post(
            f"/oauth/authorize?response_type=code&client_id={client_id}"
            f"&redirect_uri=http://localhost:5001/callback&scope=profile",
            data={"confirm": "true"},
        )
        assert resp.status_code == 302
        location = resp.headers["Location"]
        assert "code=" in location

        # 5. Exchange code for token
        from urllib.parse import urlparse, parse_qs
        code = parse_qs(urlparse(location).query)["code"][0]

        credentials = b64encode(f"{client_id}:{client_secret}".encode()).decode()
        token_resp = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://localhost:5001/callback",
            },
            headers={"Authorization": f"Basic {credentials}"},
        )
        assert token_resp.status_code == 200
        token_data = json.loads(token_resp.data)
        assert "access_token" in token_data
        assert token_data["token_type"] == "Bearer"

        # 6. Access protected resource
        access_token = token_data["access_token"]
        userinfo_resp = client.get(
            "/api/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert userinfo_resp.status_code == 200
        userinfo = json.loads(userinfo_resp.data)
        assert userinfo["username"] == "bob"

    def test_token_required_for_userinfo(self, client):
        resp = client.get("/api/userinfo")
        assert resp.status_code == 401

    def test_client_registration_page_requires_login(self, client):
        resp = client.get("/clients")
        assert resp.status_code in (301, 302)
        assert "/login" in resp.headers["Location"]

    def test_client_registration(self, app, client):
        _register_user(client, "carol", "pass123")
        resp = client.post(
            "/clients",
            data={
                "client_name": "MyApp",
                "client_uri": "http://example.com",
                "redirect_uris": "http://example.com/callback",
                "scope": "profile",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Client Registered" in resp.data
