"""OAuth2 Authorization Server – Flask application factory."""
import json
import os

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from authlib.integrations.flask_oauth2 import current_token

from .models import db, User, OAuth2Client
from .oauth2 import authorization, require_oauth, init_oauth


def create_app(config=None):
    app = Flask(__name__)

    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = "dev-secret-change-in-production"
    if not app.config.get("SQLALCHEMY_DATABASE_URI"):
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///oauth2.db"
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)

    if config:
        app.config.update(config)

    if app.config.get("TESTING"):
        os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "1"

    db.init_app(app)
    init_oauth(app)

    with app.app_context():
        db.create_all()

    # ------------------------------------------------------------------ routes

    @app.route("/")
    def index():
        user = None
        if "user_id" in session:
            user = db.session.get(User, session["user_id"])
        return render_template("index.html", user=user)

    # --- user registration / login / logout --------------------------------

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            if not username or not password:
                return render_template("register.html", error="All fields are required.")
            if User.query.filter_by(username=username).first():
                return render_template("register.html", error="Username already taken.")
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            session["user_id"] = user.id
            return redirect(url_for("index"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        next_url = request.args.get("next", url_for("index"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                session["user_id"] = user.id
                return redirect(next_url)
            return render_template("login.html", error="Invalid credentials.", next=next_url)
        return render_template("login.html", next=next_url)

    @app.route("/logout")
    def logout():
        session.pop("user_id", None)
        return redirect(url_for("index"))

    # --- OAuth2 client management ------------------------------------------

    @app.route("/clients", methods=["GET", "POST"])
    def clients():
        if "user_id" not in session:
            return redirect(url_for("login", next=request.url))
        user = db.session.get(User, session["user_id"])
        if request.method == "POST":
            client_metadata = {
                "client_name": request.form.get("client_name"),
                "client_uri": request.form.get("client_uri"),
                "redirect_uris": request.form.get("redirect_uris", "").split(),
                "scope": request.form.get("scope", "profile"),
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "client_secret_basic",
            }
            client = OAuth2Client(user_id=user.id)
            client.set_client_metadata(client_metadata)
            client.client_id = _generate_id()
            client.client_secret = _generate_id()
            db.session.add(client)
            db.session.commit()
            return render_template("client_created.html", client=client)
        user_clients = OAuth2Client.query.filter_by(user_id=user.id).all()
        return render_template("clients.html", user=user, clients=user_clients)

    # --- OAuth2 authorization endpoint -------------------------------------

    @app.route("/oauth/authorize", methods=["GET", "POST"])
    def authorize():
        if "user_id" not in session:
            return redirect(url_for("login", next=request.url))
        user = db.session.get(User, session["user_id"])
        if request.method == "GET":
            try:
                grant = authorization.get_consent_grant(end_user=user)
            except Exception as exc:
                return jsonify(error=str(exc)), 400
            return render_template("authorize.html", user=user, grant=grant)
        if request.form.get("confirm"):
            grant_user = user
        else:
            grant_user = None
        return authorization.create_authorization_response(grant_user=grant_user)

    # --- OAuth2 token endpoint ---------------------------------------------

    @app.route("/oauth/token", methods=["POST"])
    def issue_token():
        return authorization.create_token_response()

    # --- OAuth2 token revocation -------------------------------------------

    @app.route("/oauth/revoke", methods=["POST"])
    def revoke_token():
        return authorization.create_endpoint_response("revocation")

    # --- Protected resource: user info ------------------------------------

    @app.route("/api/userinfo")
    @require_oauth("profile")
    def userinfo():
        user = current_token.user
        return jsonify(id=user.id, username=user.username)

    return app


def _generate_id(length=40):
    import secrets
    return secrets.token_urlsafe(length)


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=5000)
