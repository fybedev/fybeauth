"""OAuth2 server configuration – Authlib grants and token validator."""
from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
    create_bearer_token_validator,
    create_revocation_endpoint,
)
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
    RefreshTokenGrant as _RefreshTokenGrant,
)
from authlib.oauth2.rfc7636 import CodeChallenge

from .models import db, OAuth2Client, OAuth2AuthorizationCode, OAuth2Token

authorization = AuthorizationServer()
require_oauth = ResourceProtector()


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        payload = request.payload
        code_challenge = payload.data.get("code_challenge")
        code_challenge_method = payload.data.get("code_challenge_method")
        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=payload.redirect_uri,
            scope=payload.scope,
            user_id=request.user.id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        return OAuth2AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id
        ).first()

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return authorization_code.user


class RefreshTokenGrant(_RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        token = OAuth2Token.query.filter_by(refresh_token=refresh_token).first()
        if token and token.is_refresh_token_active():
            return token
        return None

    def authenticate_user(self, credential):
        return credential.user

    def revoke_old_credential(self, credential):
        credential.revoked = True
        db.session.add(credential)
        db.session.commit()


def init_oauth(app):
    query_client = create_query_client_func(db.session, OAuth2Client)
    save_token = create_save_token_func(db.session, OAuth2Token)

    authorization.init_app(app, query_client=query_client, save_token=save_token)
    authorization.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=False)])
    authorization.register_grant(RefreshTokenGrant)

    revocation_cls = create_revocation_endpoint(db.session, OAuth2Token)
    authorization.register_endpoint(revocation_cls)

    BearerTokenValidator = create_bearer_token_validator(db.session, OAuth2Token)
    require_oauth.register_token_validator(BearerTokenValidator())
