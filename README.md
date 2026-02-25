# fybeauth

A full-stack OAuth2 Authorization Server built with **Flask** and **Authlib**, plus an **example Flask client app** that demonstrates the Authorization Code flow.

## Project structure

```
fybeauth/
├── requirements.txt          # Python dependencies
├── oauth_server/             # OAuth2 Authorization Server
│   ├── app.py                # Flask application factory
│   ├── models.py             # SQLAlchemy models
│   ├── oauth2.py             # Authlib grants & token validator
│   └── templates/            # Jinja2 HTML templates
│       ├── index.html
│       ├── login.html
│       ├── register.html
│       ├── authorize.html    # OAuth2 consent screen
│       ├── clients.html      # Client management UI
│       └── client_created.html
├── example_app/              # Example Flask OAuth2 client
│   ├── app.py
│   └── templates/
│       ├── index.html
│       └── profile.html
└── tests/
    └── test_oauth_server.py  # Pytest test suite
```

## OAuth2 endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/oauth/authorize` | GET / POST | Authorization endpoint (consent screen) |
| `/oauth/token` | POST | Token endpoint |
| `/oauth/revoke` | POST | Token revocation |
| `/api/userinfo` | GET | Protected resource – returns user info (requires `profile` scope) |

Supported grant types: **Authorization Code** (with optional PKCE) and **Refresh Token**.

## Quick start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the OAuth2 server (port 5000)

```bash
python -m oauth_server.app
```

Or with the Flask CLI:

```bash
FLASK_APP=oauth_server.app:create_app flask run --port 5000
```

### 3. Create a user account

Open http://localhost:5000/register and create an account.

### 4. Register an OAuth2 client

Log in, then go to http://localhost:5000/clients and register a new client.  
Set the **Redirect URI** to `http://localhost:5001/callback`.

Note the **Client ID** and **Client Secret** that are shown.

### 5. Start the example client app (port 5001)

```bash
OAUTH_CLIENT_ID=<client_id> \
OAUTH_CLIENT_SECRET=<client_secret> \
python -m example_app.app
```

Or:

```bash
export OAUTH_CLIENT_ID=<your-client-id>
export OAUTH_CLIENT_SECRET=<your-client-secret>
python example_app/app.py
```

### 6. Try the OAuth2 login

Open http://localhost:5001 and click **Login with FybeAuth**.  
You will be redirected to the FybeAuth consent screen, approve access, and land on the profile page.

## Running tests

```bash
pytest tests/ -v
```

## Architecture

```
Browser  ──►  Example App (port 5001)
                │   redirect to /oauth/authorize
                ▼
              FybeAuth Server (port 5000)
                │   user logs in + approves consent
                │   redirect back with ?code=...
                ▼
              Example App
                │   POST /oauth/token  (exchange code → access_token)
                │   GET  /api/userinfo (bearer token)
                ▼
              user profile page
```
