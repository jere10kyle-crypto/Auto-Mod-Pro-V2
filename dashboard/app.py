"""app.py — Auto-Mod-Pro V2 Dashboard with Discord OAuth2"""
from flask import (Flask, render_template, request, redirect, url_for,
                   jsonify, session, flash)
from functools import wraps
import os, sys, secrets, requests
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bot.db import (init_db, SessionLocal, get_guild, get_member,
                    Guild, Member, Strike, ModLog, BannedWord, Ticket, DashUser,
                    add_mod_log, xp_for_level)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

DISCORD_CLIENT_ID     = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT_URI  = os.environ.get("DISCORD_REDIRECT_URI", "http://localhost:5000/auth/callback")
OWNER_ID              = os.environ.get("OWNER_ID", "")

DISCORD_API  = "https://discord.com/api/v10"
DISCORD_AUTH = (
    "https://discord.com/api/oauth2/authorize"
    f"?client_id={DISCORD_CLIENT_ID}"
    f"&redirect_uri={{redirect_uri}}"
    "&response_type=code"
    "&scope=identify+guilds"
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def discord_request(endpoint: str, token: str) -> dict:
    r = requests.get(f"{DISCORD_API}{endpoint}",
                     headers={"Authorization": f"Bearer {token}"}, timeout=10)
    return r.json() if r.ok else {}


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def guild_access_required(f):
    @wraps(f)
    def wrapper(*args, guild_id, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        uid = str(session["user_id"])
        if uid == OWNER_ID:
            return f(*args, guild_id=guild_id, **kwargs)
        db = SessionLocal()
        try:
            g = get_guild(db, int(guild_id))
            admins = [a.strip() for a in g.dashboard_admins.split(",") if a.strip()]
            if uid not in admins:
                flash("You don't have access to that server.", "error")
                return redirect(url_for("index"))
        finally:
            db.close()
        return f(*args, guild_id=guild_id, **kwargs)
    return wrapper


def get_user_guilds(access_token: str) -> list:
    """Return guilds where user has MANAGE_GUILD (0x20) permission."""
    guilds = discord_request("/users/@me/guilds", access_token)
    if not isinstance(guilds, list):
        return []
    return [g for g in guilds if (int(g.get("permissions", 0)) & 0x20) == 0x20]


# ── OAuth2 ─────────────────────────────────────────────────────────────────────

@app.route("/auth/discord")
def auth_discord():
    state = secrets.token_hex(16)
    session["oauth_state"] = state
    redirect_uri = DISCORD_REDIRECT_URI
    url = (f"https://discord.com/api/oauth2/authorize"
           f"?client_id={DISCORD_CLIENT_ID}"
           f"&redirect_uri={requests.utils.quote(redirect_uri, safe='')}"
           f"&response_type=code&scope=identify+guilds&state={state}")
    return redirect(url)


@app.route("/auth/callback")
def auth_callback():
    code  = request.args.get("code")
    state = request.args.get("state")
    if not code or state != session.get("oauth_state"):
        flash("Authentication failed. Please try again.", "error")
        return redirect(url_for("login"))

    r = requests.post(f"{DISCORD_API}/oauth2/token", data={
        "client_id":     DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  DISCORD_REDIRECT_URI,
    }, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=10)

    if not r.ok:
        flash("Failed to exchange code. Check OAuth2 settings.", "error")
        return redirect(url_for("login"))

    tokens = r.json()
    access_token = tokens.get("access_token")

    user   = discord_request("/users/@me", access_token)
    guilds = get_user_guilds(access_token)

    if not user.get("id"):
        flash("Failed to fetch user info.", "error")
        return redirect(url_for("login"))

    session["user_id"]      = int(user["id"])
    session["username"]     = user.get("username", "Unknown")
    session["avatar"]       = user.get("avatar", "")
    session["user_guilds"]  = guilds
    session["access_token"] = access_token

    db = SessionLocal()
    try:
        du = db.query(DashUser).filter_by(id=int(user["id"])).first()
        if not du:
            du = DashUser(id=int(user["id"]), username=user["username"],
                          avatar=user.get("avatar", ""))
            db.add(du)
        else:
            du.username   = user["username"]
            du.avatar     = user.get("avatar", "")
            du.last_login = datetime.utcnow()
        db.commit()
    finally:
        db.close()

    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Pages ──────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/auth/debug")
def auth_debug():
    return jsonify({
        "client_id_set": bool(DISCORD_CLIENT_ID),
        "client_secret_set": bool(DISCORD_CLIENT_SECRET),
        "redirect_uri": DISCORD_REDIRECT_URI,
    })


@app.route("/login")
def login():
    if "user_id" in session:
        return redirect(url_for("index"))
    return render_template("login.html", client_id=DISCORD_CLIENT_ID)


@app.route("/")
@login_required
def index():
    db = SessionLocal()
    try:
        uid     = str(session["user_id"])
        guilds  = session.get("user_guilds", [])

        # Filter to guilds where bot is present (has DB entry)
        accessible = []
        for g in guilds:
            try:
                cfg = db.query(Guild).filter_by(id=int(g["id"])).first()
                if cfg or uid == OWNER_ID:
                    accessible.append(g)
            except Exception:
                pass

        return render_template("index.html",
                               guilds=accessible,
                               username=session.get("username"),
                               avatar=session.get("avatar"),
                               user_id=uid)
    finally:
        db.close()


@app.route("/dashboard/<guild_id>")
@login_required
@guild_access_required
def dashboard(guild_id):
    db = SessionLocal()
    try:
        guild_cfg = get_guild(db, int(guild_id))

        # Stats
        total_strikes   = db.query(Strike).filter_by(guild_id=int(guild_id), active=True).count()
        total_members   = db.query(Member).filter_by(guild_id=int(guild_id)).count()
        total_mod_actions = db.query(ModLog).filter_by(guild_id=int(guild_id)).count()
        open_tickets    = db.query(Ticket).filter_by(guild_id=int(guild_id), status="open").count()

        recent_logs = (db.query(ModLog)
                       .filter_by(guild_id=int(guild_id))
                       .order_by(ModLog.created_at.desc())
                       .limit(10).all())

        # Action breakdown for chart
        actions = {}
        for log in db.query(ModLog).filter_by(guild_id=int(guild_id)).all():
            actions[log.action] = actions.get(log.action, 0) + 1

        return render_template("dashboard.html",
                               guild_id=guild_id,
                               guild_cfg=guild_cfg,
                               total_strikes=total_strikes,
                               total_members=total_members,
                               total_mod_actions=total_mod_actions,
                               open_tickets=open_tickets,
                               recent_logs=recent_logs,
                               actions=actions,
                               username=session.get("username"),
                               avatar=session.get("avatar"))
    finally:
        db.close()


@app.route("/dashboard/<guild_id>/settings", methods=["GET", "POST"])
@login_required
@guild_access_required
def settings(guild_id):
    db = SessionLocal()
    try:
        guild_cfg = get_guild(db, int(guild_id))

        if request.method == "POST":
            f = request.form
            # Punishment tiers
            guild_cfg.tier1_strikes  = int(f.get("tier1_strikes", 1))
            guild_cfg.tier1_minutes  = int(f.get("tier1_minutes", 5))
            guild_cfg.tier2_strikes  = int(f.get("tier2_strikes", 2))
            guild_cfg.tier2_minutes  = int(f.get("tier2_minutes", 30))
            guild_cfg.tier3_strikes  = int(f.get("tier3_strikes", 3))
            guild_cfg.tier3_minutes  = int(f.get("tier3_minutes", 180))
            guild_cfg.tier4_strikes  = int(f.get("tier4_strikes", 4))
            guild_cfg.tier4_action   = f.get("tier4_action", "kick")
            guild_cfg.tier5_strikes  = int(f.get("tier5_strikes", 5))
            # Auto-mod
            guild_cfg.spam_enabled   = "spam_enabled"   in f
            guild_cfg.spam_threshold = int(f.get("spam_threshold", 5))
            guild_cfg.spam_window    = int(f.get("spam_window", 10))
            guild_cfg.caps_enabled   = "caps_enabled"   in f
            guild_cfg.caps_percent   = int(f.get("caps_percent", 70))
            guild_cfg.emoji_enabled  = "emoji_enabled"  in f
            guild_cfg.emoji_limit    = int(f.get("emoji_limit", 10))
            guild_cfg.mention_enabled = "mention_enabled" in f
            guild_cfg.mention_limit  = int(f.get("mention_limit", 5))
            guild_cfg.link_enabled   = "link_enabled"   in f
            guild_cfg.link_whitelist = f.get("link_whitelist", "")
            # Channels (stored as int or None)
            def ch_id(key):
                v = f.get(key, "").strip()
                return int(v) if v.isdigit() else None
            guild_cfg.mod_log_channel = ch_id("mod_log_channel")
            guild_cfg.welcome_channel = ch_id("welcome_channel")
            guild_cfg.welcome_enabled = "welcome_enabled" in f
            guild_cfg.welcome_message = f.get("welcome_message", guild_cfg.welcome_message)
            guild_cfg.auto_role_id    = ch_id("auto_role_id")
            # XP
            guild_cfg.xp_enabled     = "xp_enabled" in f
            guild_cfg.xp_per_message = int(f.get("xp_per_message", 15))
            guild_cfg.xp_cooldown    = int(f.get("xp_cooldown", 60))
            guild_cfg.level_channel  = ch_id("level_channel")
            # Raid
            guild_cfg.raid_enabled   = "raid_enabled"  in f
            guild_cfg.raid_threshold = int(f.get("raid_threshold", 10))
            guild_cfg.raid_window    = int(f.get("raid_window", 10))
            guild_cfg.raid_action    = f.get("raid_action", "kick")
            # Tickets
            guild_cfg.ticket_enabled  = "ticket_enabled" in f
            guild_cfg.ticket_category = ch_id("ticket_category")
            guild_cfg.ticket_log      = ch_id("ticket_log")
            db.commit()
            flash("Settings saved!", "success")
            return redirect(url_for("settings", guild_id=guild_id))

        banned = db.query(BannedWord).filter_by(guild_id=int(guild_id)).all()
        return render_template("settings.html",
                               guild_id=guild_id,
                               guild_cfg=guild_cfg,
                               banned_words=banned,
                               username=session.get("username"),
                               avatar=session.get("avatar"))
    finally:
        db.close()


@app.route("/dashboard/<guild_id>/users")
@login_required
@guild_access_required
def users(guild_id):
    db = SessionLocal()
    try:
        members = (db.query(Member)
                   .filter_by(guild_id=int(guild_id))
                   .order_by(Member.xp.desc())
                   .limit(100).all())
        user_data = []
        for m in members:
            sc = db.query(Strike).filter_by(
                guild_id=int(guild_id), user_id=m.user_id, active=True
            ).count()
            user_data.append({
                "user_id":   m.user_id,
                "username":  m.username or str(m.user_id),
                "xp":        m.xp,
                "level":     m.level,
                "messages":  m.messages,
                "strikes":   sc,
                "shadow_muted": m.shadow_muted,
            })
        return render_template("users.html",
                               guild_id=guild_id,
                               users=user_data,
                               username=session.get("username"),
                               avatar=session.get("avatar"))
    finally:
        db.close()


# ── API endpoints (called by dashboard JS) ─────────────────────────────────────

@app.route("/api/<guild_id>/banned_words", methods=["GET"])
@login_required
def api_banned_words(guild_id):
    db = SessionLocal()
    try:
        rows = db.query(BannedWord).filter_by(guild_id=int(guild_id)).all()
        return jsonify([{"id": r.id, "word": r.word} for r in rows])
    finally:
        db.close()


@app.route("/api/<guild_id>/banned_words/add", methods=["POST"])
@login_required
def api_add_word(guild_id):
    word = request.json.get("word", "").strip().lower()
    if not word:
        return jsonify({"error": "Empty word"}), 400
    db = SessionLocal()
    try:
        existing = db.query(BannedWord).filter_by(guild_id=int(guild_id), word=word).first()
        if existing:
            return jsonify({"error": "Already banned"}), 409
        bw = BannedWord(guild_id=int(guild_id), word=word)
        db.add(bw)
        db.commit()
        return jsonify({"id": bw.id, "word": bw.word})
    finally:
        db.close()


@app.route("/api/<guild_id>/banned_words/<int:word_id>", methods=["DELETE"])
@login_required
def api_delete_word(guild_id, word_id):
    db = SessionLocal()
    try:
        row = db.query(BannedWord).filter_by(id=word_id, guild_id=int(guild_id)).first()
        if row:
            db.delete(row)
            db.commit()
        return jsonify({"ok": True})
    finally:
        db.close()


@app.route("/api/<guild_id>/clear_strikes/<int:user_id>", methods=["POST"])
@login_required
def api_clear_strikes(guild_id, user_id):
    db = SessionLocal()
    try:
        db.query(Strike).filter_by(
            guild_id=int(guild_id), user_id=user_id, active=True
        ).update({"active": False})
        db.commit()
        return jsonify({"ok": True})
    finally:
        db.close()


# ── Init & run ─────────────────────────────────────────────────────────────────

init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
