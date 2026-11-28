"""Who is calling: HS256 JWT bearer tokens, shared by the HTTP gateway and the REST decision point.

When MCP_GUARD_JWT_SECRET is set, a caller must send `Authorization: Bearer <JWT>` signed with it, for the audience
MCP_GUARD_JWT_AUDIENCE (default "mcp-guard"). The user is the token's `sub`; roles it claims are kept only where the
policy grants them. Without the secret, identity checks are off (local development only).
"""
import os

import jwt


class AuthError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def enabled() -> bool:
    return bool(os.environ.get("MCP_GUARD_JWT_SECRET"))


def claims(authorization: str | None) -> dict | None:
    """Decoded token, or None when JWT identity is switched off. Raises AuthError on a missing or bad token."""
    secret = os.environ.get("MCP_GUARD_JWT_SECRET")
    if not secret:
        return None
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthError(401, "bearer token required")
    try:
        c = jwt.decode(authorization.split(" ", 1)[1], secret, algorithms=["HS256"],
                       audience=os.environ.get("MCP_GUARD_JWT_AUDIENCE", "mcp-guard"))
    except jwt.PyJWTError as e:
        raise AuthError(401, f"invalid token: {e}") from e
    if not c.get("sub"):
        raise AuthError(401, "token has no sub")
    return c
