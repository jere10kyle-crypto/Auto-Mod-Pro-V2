"""db.py — SQLAlchemy models for Auto-Mod-Pro V2"""
import os
from datetime import datetime
from sqlalchemy import (create_engine, Column, Integer, String, Boolean,
                        DateTime, Text, BigInteger)
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///data/bot.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

_kwargs = {}
if "postgresql" in DATABASE_URL:
    _kwargs = {"pool_pre_ping": True, "pool_size": 5, "max_overflow": 10}

engine = create_engine(DATABASE_URL, **_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()


class Guild(Base):
    __tablename__ = "guilds"
    id               = Column(BigInteger, primary_key=True)
    mod_log_channel  = Column(BigInteger, nullable=True)
    mute_role_id     = Column(BigInteger, nullable=True)
    tier1_strikes    = Column(Integer, default=1)
    tier1_minutes    = Column(Integer, default=5)
    tier2_strikes    = Column(Integer, default=2)
    tier2_minutes    = Column(Integer, default=30)
    tier3_strikes    = Column(Integer, default=3)
    tier3_minutes    = Column(Integer, default=180)
    tier4_strikes    = Column(Integer, default=4)
    tier4_action     = Column(String(10), default="kick")
    tier5_strikes    = Column(Integer, default=5)
    spam_enabled     = Column(Boolean, default=True)
    spam_threshold   = Column(Integer, default=5)
    spam_window      = Column(Integer, default=10)
    caps_enabled     = Column(Boolean, default=True)
    caps_percent     = Column(Integer, default=70)
    emoji_enabled    = Column(Boolean, default=True)
    emoji_limit      = Column(Integer, default=10)
    mention_enabled  = Column(Boolean, default=True)
    mention_limit    = Column(Integer, default=5)
    link_enabled     = Column(Boolean, default=False)
    link_whitelist   = Column(Text, default="")
    raid_enabled     = Column(Boolean, default=True)
    raid_threshold   = Column(Integer, default=10)
    raid_window      = Column(Integer, default=10)
    raid_action      = Column(String(10), default="kick")
    lockdown         = Column(Boolean, default=False)
    welcome_enabled  = Column(Boolean, default=False)
    welcome_channel  = Column(BigInteger, nullable=True)
    welcome_message  = Column(Text, default="Welcome {user} to **{server}**!")
    auto_role_id     = Column(BigInteger, nullable=True)
    xp_enabled       = Column(Boolean, default=True)
    xp_per_message   = Column(Integer, default=15)
    xp_cooldown      = Column(Integer, default=60)
    level_channel    = Column(BigInteger, nullable=True)
    ticket_enabled   = Column(Boolean, default=False)
    ticket_category  = Column(BigInteger, nullable=True)
    ticket_log       = Column(BigInteger, nullable=True)
    verify_enabled   = Column(Boolean, default=False)
    verify_role_id   = Column(BigInteger, nullable=True)
    dashboard_admins = Column(Text, default="")


class Member(Base):
    __tablename__ = "members"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    guild_id     = Column(BigInteger, index=True)
    user_id      = Column(BigInteger, index=True)
    username     = Column(String(100), default="")
    xp           = Column(Integer, default=0)
    level        = Column(Integer, default=0)
    messages     = Column(Integer, default=0)
    last_xp_at   = Column(DateTime, default=datetime.utcnow)
    shadow_muted = Column(Boolean, default=False)


class Strike(Base):
    __tablename__ = "strikes"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    guild_id     = Column(BigInteger, index=True)
    user_id      = Column(BigInteger, index=True)
    moderator_id = Column(BigInteger)
    reason       = Column(Text, default="No reason provided")
    created_at   = Column(DateTime, default=datetime.utcnow)
    active       = Column(Boolean, default=True)


class ModLog(Base):
    __tablename__ = "mod_logs"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    guild_id     = Column(BigInteger, index=True)
    user_id      = Column(BigInteger)
    username     = Column(String(100), default="")
    moderator_id = Column(BigInteger)
    action       = Column(String(20))
    reason       = Column(Text, default="")
    duration     = Column(Integer, nullable=True)
    created_at   = Column(DateTime, default=datetime.utcnow)


class BannedWord(Base):
    __tablename__ = "banned_words"
    id       = Column(Integer, primary_key=True, autoincrement=True)
    guild_id = Column(BigInteger, index=True)
    word     = Column(String(200))


class AutoResponse(Base):
    __tablename__ = "auto_responses"
    id       = Column(Integer, primary_key=True, autoincrement=True)
    guild_id = Column(BigInteger, index=True)
    trigger  = Column(String(200))
    response = Column(Text)
    enabled  = Column(Boolean, default=True)


class Ticket(Base):
    __tablename__ = "tickets"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    guild_id   = Column(BigInteger, index=True)
    user_id    = Column(BigInteger)
    channel_id = Column(BigInteger, unique=True)
    status     = Column(String(20), default="open")
    created_at = Column(DateTime, default=datetime.utcnow)
    closed_at  = Column(DateTime, nullable=True)


class DashUser(Base):
    __tablename__ = "dash_users"
    id             = Column(BigInteger, primary_key=True)
    username       = Column(String(100))
    avatar         = Column(String(200), default="")
    managed_guilds = Column(Text, default="")
    last_login     = Column(DateTime, default=datetime.utcnow)


def init_db():
    os.makedirs("data", exist_ok=True)
    Base.metadata.create_all(engine, checkfirst=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_guild(db, guild_id: int) -> Guild:
    g = db.query(Guild).filter_by(id=guild_id).first()
    if not g:
        g = Guild(id=guild_id)
        db.add(g)
        db.commit()
    return g


def get_member(db, guild_id: int, user_id: int, username: str = "") -> Member:
    m = db.query(Member).filter_by(guild_id=guild_id, user_id=user_id).first()
    if not m:
        m = Member(guild_id=guild_id, user_id=user_id, username=username)
        db.add(m)
        db.commit()
    elif username and m.username != username:
        m.username = username
        db.commit()
    return m


def strike_count(db, guild_id: int, user_id: int) -> int:
    return db.query(Strike).filter_by(
        guild_id=guild_id, user_id=user_id, active=True
    ).count()


def add_strike(db, guild_id: int, user_id: int, moderator_id: int, reason: str) -> int:
    s = Strike(guild_id=guild_id, user_id=user_id,
               moderator_id=moderator_id, reason=reason)
    db.add(s)
    db.commit()
    return strike_count(db, guild_id, user_id)


def add_mod_log(db, guild_id: int, user_id: int, username: str,
                moderator_id: int, action: str, reason: str = "", duration: int = None):
    log = ModLog(guild_id=guild_id, user_id=user_id, username=username,
                 moderator_id=moderator_id, action=action,
                 reason=reason, duration=duration)
    db.add(log)
    db.commit()


def xp_for_level(level: int) -> int:
    return int(100 * (level ** 1.5))
