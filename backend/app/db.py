import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, String, Text, JSON, ForeignKey, DateTime, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

def now():
    return datetime.now(timezone.utc)

engine = create_engine(os.environ.get('DATABASE_URL', 'postgresql+psycopg://incidentdesk:incidentdesk@localhost/incidentdesk'), pool_pre_ping=True)
Session = sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20))

class LoginSession(Base):
    __tablename__ = 'sessions'
    token: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    csrf: Mapped[str] = mapped_column(String(64))
    expires: Mapped[datetime] = mapped_column(DateTime(timezone=True))

class LoginAttempt(Base):
    __tablename__ = 'login_attempts'
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    count: Mapped[int] = mapped_column(default=0)
    window: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Upload(Base):
    __tablename__ = 'uploads'
    id: Mapped[int] = mapped_column(primary_key=True)
    digest: Mapped[str] = mapped_column(String(64), unique=True)
    filename: Mapped[str] = mapped_column(String(120))
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    status: Mapped[str] = mapped_column(String(20), default='queued')
    payload: Mapped[list | None] = mapped_column(JSON, nullable=True)
    event_count: Mapped[int] = mapped_column(Integer)
    synthetic: Mapped[bool] = mapped_column(default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    attempts: Mapped[int] = mapped_column(default=0)
    lease: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Case(Base):
    __tablename__ = 'cases'
    id: Mapped[int] = mapped_column(primary_key=True)
    upload_id: Mapped[int] = mapped_column(ForeignKey('uploads.id'), index=True)
    title: Mapped[str] = mapped_column(String(300))
    host: Mapped[str] = mapped_column(String(120))
    username: Mapped[str] = mapped_column(String(120))
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default='open')
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    version: Mapped[int] = mapped_column(default=1)
    evidence: Mapped[list] = mapped_column(JSON)
    findings: Mapped[list] = mapped_column(JSON)
    synthetic: Mapped[bool] = mapped_column(default=False)
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Activity(Base):
    __tablename__ = 'activities'
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey('cases.id'), nullable=True, index=True)
    actor: Mapped[str] = mapped_column(String(80))
    kind: Mapped[str] = mapped_column(String(40))
    detail: Mapped[str] = mapped_column(Text)
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

def db():
    with Session() as session:
        yield session

def audit(session, actor, kind, detail, case_id=None):
    session.add(Activity(actor=actor, kind=kind, detail=detail, case_id=case_id))
