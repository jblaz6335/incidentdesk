import hashlib
import os
import secrets
from datetime import timedelta, timezone
from fastapi import Depends, HTTPException, Request
from pwdlib import PasswordHash
from sqlalchemy import select
from .db import db, LoginSession, User, now, utc

passwords = PasswordHash.recommended()
DUMMY = passwords.hash(secrets.token_urlsafe(32))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def current(request: Request, s=Depends(db)):
    token = request.cookies.get("incidentdesk_session", "")
    session = s.get(LoginSession, digest(token)) if token else None
    if not session or utc(session.expires) <= now():
        raise HTTPException(401, "Sign in to continue.")
    user = s.get(User, session.user_id)
    if not user or user.role not in ("analyst", "administrator"):
        raise HTTPException(403, "Account is not authorized.")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if not secrets.compare_digest(
            request.headers.get("x-csrf-token", ""), session.csrf
        ):
            raise HTTPException(403, "Invalid CSRF token. Refresh and try again.")
    request.state.session = session
    return user


def admin(user=Depends(current)):
    if user.role != "administrator":
        raise HTTPException(403, "Administrator access required.")
    return user
