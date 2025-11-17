from __future__ import annotations
import os, sqlite3, secrets, hashlib, hmac
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Tuple

from flask import Flask, render_template, request, redirect, make_response, g, url_for

# ================== Infra DB ==================
class DB:
    def __init__(self, path: str = "skinperfect.db"):
        self.path = path
        self._ensure_schema()

    def _ensure_schema(self):
        with sqlite3.connect(self.path) as conn:
            cur = conn.cursor()
            cur.execute("""
            CREATE TABLE IF NOT EXISTS users(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              email TEXT NOT NULL UNIQUE,
              pwd_hash BLOB NOT NULL,
              pwd_salt BLOB NOT NULL,
              last_login_at TEXT,
              terms_consent INTEGER NOT NULL DEFAULT 0,
              consent_at TEXT
            )""")
            cur.execute("""
            CREATE TABLE IF NOT EXISTS routines(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(user_id) REFERENCES users(id)
            )""")
            cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions(
              id TEXT PRIMARY KEY,
              user_id INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              FOREIGN KEY(user_id) REFERENCES users(id)
            )""")
            cur.execute("""
            CREATE TABLE IF NOT EXISTS recovery_tokens(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              token_hash BLOB NOT NULL,
              created_at TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              used_at TEXT,
              FOREIGN KEY(user_id) REFERENCES users(id)
            )""")
            conn.commit()

    def connect(self):
        return sqlite3.connect(self.path)


# ================== Segurança de senha ==================
class PasswordHasher:
    def __init__(self, iterations: int = 310_000, dklen: int = 32):
        self.iterations = iterations
        self.dklen = dklen

    def make_hash(self, password: str) -> Tuple[bytes, bytes]:
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                  self.iterations, dklen=self.dklen)
        return key, salt

    def verify(self, password: str, expected_hash: bytes, salt: bytes) -> bool:
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                  self.iterations, dklen=self.dklen)
        return hmac.compare_digest(key, expected_hash)


# ================== Entidades ==================
@dataclass
class User:
    id: int
    name: str
    email: str
    last_login_at: Optional[str]
    terms_consent: bool
    consent_at: Optional[str]


@dataclass
class Session:
    id: str
    user_id: int
    created_at: str
    expires_at: str


# ================== Repositórios ==================
class UserRepository:
    def __init__(self, db: DB, hasher: PasswordHasher):
        self.db = db
        self.hasher = hasher

    def create_user(self, name: str, email: str, password: str,
                    terms_consent: bool) -> User:
        email_norm = email.lower().strip()
        pwd_hash, pwd_salt = self.hasher.make_hash(password)
        consent_at = datetime.utcnow().isoformat() if terms_consent else None
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users(name, email, pwd_hash, pwd_salt, terms_consent, consent_at) "
                "VALUES(?,?,?,?,?,?)",
                (name, email_norm, pwd_hash, pwd_salt,
                 1 if terms_consent else 0, consent_at),
            )
            user_id = cur.lastrowid
            conn.commit()
        return self.get_by_id(user_id)

    def get_by_email_with_secret(self, email: str):
        email_norm = email.lower().strip()
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id,name,email,pwd_hash,pwd_salt,last_login_at,terms_consent,consent_at "
                "FROM users WHERE email=?",
                (email_norm,),
            )
            return cur.fetchone()

    def get_by_id(self, user_id: int) -> Optional[User]:
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id,name,email,last_login_at,terms_consent,consent_at "
                "FROM users WHERE id=?",
                (user_id,),
            )
            r = cur.fetchone()
            if not r:
                return None
            return User(
                id=r[0],
                name=r[1],
                email=r[2],
                last_login_at=r[3],
                terms_consent=bool(r[4]),
                consent_at=r[5],
            )

    def set_last_login(self, user_id: int):
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET last_login_at=? WHERE id=?",
                (datetime.utcnow().isoformat(), user_id),
            )
            conn.commit()

    def change_password(self, user_id: int, new_password: str):
        pwd_hash, pwd_salt = self.hasher.make_hash(new_password)
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET pwd_hash=?, pwd_salt=? WHERE id=?",
                (pwd_hash, pwd_salt, user_id),
            )
            conn.commit()


class RoutineService:
    def __init__(self, db: DB):
        self.db = db

    def create_initial_empty(self, user_id: int):
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO routines(user_id, created_at) VALUES(?,?)",
                (user_id, datetime.utcnow().isoformat()),
            )
            conn.commit()


class SessionManager:
    def __init__(self, db: DB, ttl_minutes: int = 60):
        self.db = db
        self.ttl = ttl_minutes

    def create(self, user_id: int) -> Session:
        sid = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        exp = now + timedelta(minutes=self.ttl)
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO sessions(id, user_id, created_at, expires_at) "
                "VALUES(?,?,?,?)",
                (sid, user_id, now.isoformat(), exp.isoformat()),
            )
            conn.commit()
        return Session(id=sid, user_id=user_id,
                       created_at=now.isoformat(),
                       expires_at=exp.isoformat())# ================== Flask app ==================
db = DB()
auth = AuthService(db)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY",
                                          "dev-secret-change-me")


@app.before_request
def load_current_user():
    g.current_user = None
    sid = request.cookies.get("session_id")
    if not sid:
        return
    user = auth.validate_session(sid)
    if user:
        g.current_user = user


@app.get("/")
def index():
    if g.current_user:
        return redirect(url_for("home"))
    message = request.args.get("message")
    error = request.args.get("error")
    return render_template("index.html", message=message, error=error)


@app.post("/register")
def register():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    accepted_terms = request.form.get("terms") == "on"

    try:
        auth.register(name, email, password, accepted_terms)
    except Exception as e:
        return render_template("index.html", error=str(e), message=None)

    # login automático após cadastro
    user, session = auth.login(email, password)
    resp = make_response(redirect(url_for("home")))
    resp.set_cookie("session_id", session.id,
                    httponly=True, samesite="Lax")
    return resp


@app.post("/login")
def login():
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    try:
        user, session = auth.login(email, password)
    except Exception as e:
        return render_template("index.html", error=str(e), message=None)

    resp = make_response(redirect(url_for("home")))
    resp.set_cookie("session_id", session.id,
                    httponly=True, samesite="Lax")
    return resp


@app.get("/home")
def home():
    if not g.current_user:
        return redirect(url_for("index",
                                error="Você precisa estar logado."))
    return render_template("home.html", user=g.current_user)


@app.get("/logout")
def logout():
    resp = make_response(
        redirect(url_for("index", message="Sessão encerrada."))
    )
    resp.delete_cookie("session_id")
    return resp


@app.get("/forgot-password")
def forgot_password_form():
    return render_template("forgot_password.html",
                           message=None, error=None)


@app.post("/forgot-password")
def forgot_password():
    email = request.form.get("email", "").strip()
    token = auth.request_password_reset(email)
    if not token:
        return render_template("forgot_password.html",
                               error="E-mail não encontrado.",
                               message=None)
    msg = ("Se o e-mail existir, um link de recuperação foi enviado "
           "(simulado no console).")
    return render_template("forgot_password.html",
                           message=msg, error=None)


@app.get("/reset-password")
def reset_password_form():
    email = request.args.get("email", "")
    token = request.args.get("token", "")
    if not email or not token:
        return redirect(url_for("index",
                                error="Link de recuperação inválido."))
    return render_template("reset_password.html",
                           email=email, token=token, error=None)


@app.post("/reset-password")
def reset_password():
    email = request.form.get("email", "")
    token = request.form.get("token", "")
    new_password = request.form.get("password", "")

    ok = auth.reset_password_with_token(email, token, new_password)
    if not ok:
        return render_template(
            "reset_password.html",
            email=email,
            token=token,
            error="Token inválido ou expirado.",
        )
    return redirect(url_for("index",
                            message="Senha alterada com sucesso. "
                                    "Faça login."))


if __name__ == "__main__":
    app.run(debug=True)

    def validate(self, sid: str) -> Optional[Session]:
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id,user_id,created_at,expires_at FROM sessions "
                "WHERE id=?",
                (sid,),
            )
            r = cur.fetchone()
            if not r:
                return None
            if datetime.fromisoformat(r[3]) < datetime.utcnow():
                cur.execute("DELETE FROM sessions WHERE id=?", (sid,))
                conn.commit()
                return None
            return Session(id=r[0], user_id=r[1],
                           created_at=r[2], expires_at=r[3])


# ================== E-mail (simulado) ==================
class EmailService:
    def send_password_recovery(self, to_email: str, link: str):
        msg = (
            f"[SkinPerfect] Recuperação de senha\n"
            f"Para: {to_email}\n"
            f"Link seguro: {link}\n"
            f"Enviado em: {datetime.utcnow().isoformat()}"
        )
        print("\n=== EMAIL SIMULADO ===\n" + msg + "\n======================\n")


# ================== Recuperação de senha ==================
class RecoveryService:
    def __init__(self, db: DB, token_ttl_minutes: int = 15):
        self.db = db
        self.token_ttl = token_ttl_minutes

    def _hash_token(self, token: str) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", token.encode("utf-8"), b"__recovery__", 200_000, dklen=32
        )

    def generate_and_store(self, user_id: int) -> str:
        token = secrets.token_urlsafe(24)
        token_hash = self._hash_token(token)
        now = datetime.utcnow()
        expires = now + timedelta(minutes=self.token_ttl)
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO recovery_tokens(user_id, token_hash, created_at, expires_at) "
                "VALUES(?,?,?,?)",
                (user_id, token_hash, now.isoformat(), expires.isoformat()),
            )
            conn.commit()
        return token

    def validate_token(self, email: str, token: str) -> Optional[int]:
        token_hash = self._hash_token(token)
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT rt.id, rt.token_hash, rt.expires_at, rt.used_at
                FROM recovery_tokens rt
                JOIN users u ON u.id = rt.user_id
                WHERE u.email=?
                """,
                (email.lower().strip(),),
            )
            rows = cur.fetchall()
            if not rows:
                return None
            now = datetime.utcnow()
            for rid, stored_hash, expires_at, used_at in rows:
                if used_at:
                    continue
                if datetime.fromisoformat(expires_at) < now:
                    continue
                if hmac.compare_digest(token_hash, stored_hash):
                    return rid
            return None

    def mark_used(self, token_id: int):
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE recovery_tokens SET used_at=? WHERE id=?",
                (datetime.utcnow().isoformat(), token_id),
            )
            conn.commit()

    def get_user_id_from_token(self, token_id: int) -> Optional[int]:
        with self.db.connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT user_id FROM recovery_tokens WHERE id=?",
                        (token_id,))
            r = cur.fetchone()
            return r[0] if r else None


# ================== Serviço de Autenticação ==================
class AuthService:
    def __init__(self, db: DB):
        self.db = db
        self.hasher = PasswordHasher()
        self.users = UserRepository(db, self.hasher)
        self.routines = RoutineService(db)
        self.sessions = SessionManager(db)
        self.recovery = RecoveryService(db)
        self.email = EmailService()

    # 4) criação de usuário + 5) rotina inicial + consentimento
    def register(self, name: str, email: str, password: str,
                 accepted_terms: bool) -> User:
        if not accepted_terms:
            raise ValueError("É necessário aceitar os termos de uso.")
        user = self.users.create_user(name, email, password,
                                      terms_consent=True)
        self.routines.create_initial_empty(user.id)
        return user

    # 1) credenciais + 2) sessão + 3) último acesso
    def login(self, email: str, password: str) -> Tuple[User, Session]:
        row = self.users.get_by_email_with_secret(email)
        if not row:
            raise ValueError("Credenciais inválidas.")
        user_id, name, email_db, pwd_hash, pwd_salt, last_login_at, \
            terms_consent, consent_at = row
        if not self.hasher.verify(password, pwd_hash, pwd_salt):
            raise ValueError("Credenciais inválidas.")
        session = self.sessions.create(user_id)
        self.users.set_last_login(user_id)
        user = User(
            id=user_id,
            name=name,
            email=email_db,
            last_login_at=last_login_at,
            terms_consent=bool(terms_consent),
            consent_at=consent_at,
        )
        return user, session

    def validate_session(self, session_id: str) -> Optional[User]:
        s = self.sessions.validate(session_id)
        if not s:
            return None
        return self.users.get_by_id(s.user_id)

    # 6, 7 e 8) fluxo de recuperação
    def request_password_reset(self, email: str) -> Optional[str]:
        row = self.users.get_by_email_with_secret(email)
        if not row:
            return None
        user_id = row[0]
        email_db = row[2]
        token = self.recovery.generate_and_store(user_id)
        link = url_for("reset_password", email=email_db, token=token,
                       _external=True)
        self.email.send_password_recovery(email_db, link)
        return token

    def reset_password_with_token(self, email: str, token: str,
                                  new_password: str) -> bool:
        token_id = self.recovery.validate_token(email, token)
        if not token_id:
            return False
        user_id = self.recovery.get_user_id_from_token(token_id)
        if not user_id:
            return False
        self.users.change_password(user_id, new_password)
        self.recovery.mark_used(token_id)
        return True


# ================== Flask app ==================
db = DB()
auth = AuthService(db)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY",
                                          "dev-secret-change-me")


@app.before_request
def load_current_user():
    g.current_user = None
    sid = request.cookies.get("session_id")
    if not sid:
        return
    user = auth.validate_session(sid)
    if user:
        g.current_user = user


@app.get("/")
def index():
    if g.current_user:
        return redirect(url_for("home"))
    message = request.args.get("message")
    error = request.args.get("error")
    return render_template("index.html", message=message, error=error)


@app.post("/register")
def register():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    accepted_terms = request.form.get("terms") == "on"

    try:
        auth.register(name, email, password, accepted_terms)
    except Exception as e:
        return render_template("index.html", error=str(e), message=None)

    # login automático após cadastro
    user, session = auth.login(email, password)
    resp = make_response(redirect(url_for("home")))
    resp.set_cookie("session_id", session.id,
                    httponly=True, samesite="Lax")
    return resp


@app.post("/login")
def login():
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    try:
        user, session = auth.login(email, password)
    except Exception as e:
        return render_template("index.html", error=str(e), message=None)

    resp = make_response(redirect(url_for("home")))
    resp.set_cookie("session_id", session.id,
                    httponly=True, samesite="Lax")
    return resp


@app.get("/home")
def home():
    if not g.current_user:
        return redirect(url_for("index",
                                error="Você precisa estar logado."))
    return render_template("home.html", user=g.current_user)


@app.get("/logout")
def logout():
    resp = make_response(
        redirect(url_for("index", message="Sessão encerrada."))
    )
    resp.delete_cookie("session_id")
    return resp


@app.get("/forgot-password")
def forgot_password_form():
    return render_template("forgot_password.html",
                           message=None, error=None)


@app.post("/forgot-password")
def forgot_password():
    email = request.form.get("email", "").strip()
    token = auth.request_password_reset(email)
    if not token:
        return render_template("forgot_password.html",
                               error="E-mail não encontrado.",
                               message=None)
    msg = ("Se o e-mail existir, um link de recuperação foi enviado "
           "(simulado no console).")
    return render_template("forgot_password.html",
                           message=msg, error=None)


@app.get("/reset-password")
def reset_password_form():
    email = request.args.get("email", "")
    token = request.args.get("token", "")
    if not email or not token:
        return redirect(url_for("index",
                                error="Link de recuperação inválido."))
    return render_template("reset_password.html",
                           email=email, token=token, error=None)


@app.post("/reset-password")
def reset_password():
    email = request.form.get("email", "")
    token = request.form.get("token", "")
    new_password = request.form.get("password", "")

    ok = auth.reset_password_with_token(email, token, new_password)
    if not ok:
        return render_template(
            "reset_password.html",
            email=email,
            token=token,
            error="Token inválido ou expirado.",
        )
    return redirect(url_for("index",
                            message="Senha alterada com sucesso. "
                                    "Faça login."))


if __name__ == "__main__":
    app.run(debug=True)