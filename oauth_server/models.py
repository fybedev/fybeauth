"""OAuth2 Authorization Server – models (User, Client, Token, AuthCode)."""
import time

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from authlib.integrations.sqla_oauth2 import (
    OAuth2AuthorizationCodeMixin,
    OAuth2ClientMixin,
    OAuth2TokenMixin,
)

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_user_id(self):
        return self.id

    def __repr__(self):
        return f"<User {self.username}>"


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = "oauth2_clients"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"))
    user = db.relationship("User")


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = "oauth2_codes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"))
    user = db.relationship("User")


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = "oauth2_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"))
    user = db.relationship("User")

    def is_refresh_token_active(self):
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time.time()
