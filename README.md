# Secure SDLC Remediation — Flask REST API

This repository takes the vulnerable Flask API described in the assignment
scenario and remediates each known weakness: unsalted MD5 password storage,
hardcoded API credentials, SQL injection via string-concatenated queries, and
an unauthenticated `/admin` endpoint. It also adds an automated security gate
to the CI/CD pipeline so these classes of issue are caught before merge, not
after deployment.

---

## 1. STRIDE Threat Model

| STRIDE Category | Threat | Targeted Component | Mitigation |
|---|---|---|---|
| **Spoofing** | An attacker authenticates as a legitimate user using stolen, guessed, or brute-forced credentials | `/login` endpoint | Salted bcrypt password hashing (removes the ability to crack weak hashes at scale) combined with rate limiting/account lockout on repeated failed attempts |
| **Tampering** | An attacker modifies the intended SQL query logic by injecting characters through the username or password fields | Database query construction in `/login` and `/register` | Parameterized queries (prepared statements) — user input is bound as a value, never concatenated into the query string |
| **Repudiation** | A user (or attacker) denies having performed an action, such as registering an account or accessing `/admin`, because no record ties the action to them | Application-wide action logging, particularly around `/admin` | Centralized, timestamped logging of authentication events and admin access, attributed to the API key or session used |
| **Information Disclosure** | If the database is ever breached, unsalted MD5 password hashes can be reversed in bulk using precomputed rainbow tables, exposing effectively-plaintext passwords | Password storage / database | Salted bcrypt hashing — a unique salt per password defeats rainbow tables, and bcrypt's deliberate slowness makes brute-forcing each hash individually impractical |
| **Denial of Service** | An attacker sends a high volume of requests to `/login` or `/register`, exhausting server resources or forcing repeated expensive hash computations | `/login`, `/register` endpoints | Rate limiting per source IP/account (e.g., via Flask-Limiter), separate from any network-layer rate limiting |
| **Elevation of Privilege** | An attacker accesses `/admin` directly with no credentials at all, since the endpoint previously had no authentication check | `/admin` endpoint | Authentication middleware (`require_auth`) requiring a valid API key before the route logic ever executes |

---

## 2. OWASP Top 10 Remediation

### 2a. Injection (SQL Injection)

**Insecure pattern (original):**
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)
```

**Remediated pattern (this repository, `app.py`):**
```python
row = conn.execute(
    "SELECT password_hash FROM users WHERE username = ?", (username,)
).fetchone()

if row is None or not verify_password(password, row["password_hash"]):
    return jsonify({"error": "invalid credentials"}), 401
```

The insecure version builds the query by directly inserting user input into
the SQL string, so a username like `' OR '1'='1` changes the query's actual
logic and can bypass authentication entirely or leak arbitrary rows. The fix
does two things at once: it uses a parameterized placeholder (`?`) so the
database driver treats `username` strictly as a value and never as part of
the query's syntax, and it removes the password from the query altogether —
since passwords are now stored as bcrypt hashes, the comparison has to happen
in application code via `verify_password`, not as a SQL string match.

### 2b. Broken Access Control

**Insecure pattern (original):**
```python
@app.route('/admin')
def admin():
    return jsonify({"message": "Welcome to admin panel", "users": get_all_users()})
```

**Remediated pattern (this repository, `app.py`):**
```python
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")
        if not api_key or api_key != ADMIN_API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/admin", methods=["GET"])
@require_auth
def admin():
    conn = get_db()
    users = conn.execute("SELECT id, username FROM users").fetchall()
    conn.close()
    return jsonify({"users": [dict(u) for u in users]}), 200
```

The insecure version has no access check whatsoever — anyone who requests
`/admin` gets the response, regardless of who they are. The fix wraps the
route in a `require_auth` decorator that checks for a valid `X-API-Key`
header before the route's actual logic ever runs; a request without the
correct key is rejected with a 401 before it ever touches the database.

---

## 3. Secure Password Hashing

Implemented in `hash_password.py` using **bcrypt**.

```python
import bcrypt

def hash_password(plain_text: str) -> str:
    """Generate a unique salt and return the salted bcrypt hash as a string."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_text.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_text: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a previously stored bcrypt hash."""
    return bcrypt.checkpw(plain_text.encode("utf-8"), stored_hash.encode("utf-8"))
```

**Actual output from running `python3 hash_password.py`, hashing the same
password twice:**
```
Hash 1: $2b$12$ewiGFtUka7a/wn0mO.jZ6eLdVmcK5OGwUbGLlE.llEJImb68vngFK
Hash 2: $2b$12$3J1C03byXrLNfiACRgXeZO/zgfnypRviCh7u87WvtULyw4i2FyPEe
Hashes are different: True
verify_password(pw, h1): True
verify_password(pw, h2): True
verify_password('wrong', h1): False
```
Both hashes verify correctly against the same original password, despite
being completely different strings — proving each call generated its own
random salt rather than reusing one.

**Why MD5 is unsuitable for password storage:** MD5 is a general-purpose
hash function designed to be fast, which is exactly the wrong property for
password storage — it lets an attacker who steals the database compute
billions of guesses per second on commodity hardware. MD5 also has no
built-in salting, so identical passwords produce identical hashes, making
precomputed rainbow tables effective at reversing large batches of hashes at
once instead of one at a time. MD5 additionally has known cryptographic
collision weaknesses, meaning distinct inputs can be found that produce the
same hash. Bcrypt addresses all three: it generates a unique random salt per
password automatically (defeating rainbow tables), it's deliberately slow
and tunable via a work factor (defeating brute-force speed), and it isn't
used as a general-purpose collision-sensitive hash in the first place.

---

## 4. Secret Management

**Hardcoded pattern (original):**
```python
API_KEY = "EXAMPLE_API_KEY..."
DB_PASSWORD = "EXAMPLE_PASSWORD!"
```

**Refactored pattern (this repository, `app.py`):**
```python
from dotenv import load_dotenv
import os

load_dotenv()

ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")
DB_PATH = os.environ.get("DB_PATH", "app.db")
```

**`.env.example`** (included in this repository, placeholder values only):
```
FLASK_SECRET_KEY=change_this_to_a_long_random_string
ADMIN_API_KEY=change_this_to_a_long_random_string
DB_PATH=app.db
```

**`.gitignore`** (relevant line):
```
.env
```

**Why hardcoding secrets is dangerous even in a private repository:** A
secret committed to source code doesn't just exist in the current file — it
persists in the full git history, retrievable from old commits by anyone
who ever had access, even after the line is later removed or the repo is
made public by mistake. Environment variables also make routine credential
rotation practical: rotating a hardcoded secret on a healthy 30-90 day cycle
means editing and redeploying source code every time, whereas rotating an
environment-variable-backed secret only requires updating the value in the
deployment environment or secrets manager, with no code change at all — a
discipline that's realistically unsustainable if secrets are baked into the
codebase itself.

---

## 5. CI/CD Security Gate

**`.github/workflows/security.yml`:**
```yaml
name: Security Gate

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install bandit semgrep

      - name: Run Bandit (SAST) - fails on Medium/High severity findings
        run: bandit -r . -ll

      - name: Run Semgrep (additional SAST, p/python ruleset)
        run: semgrep --config p/python --error
```

The `-ll` flag tells Bandit to only report Medium and High severity issues
(skipping Low); Bandit returns a non-zero exit code whenever it finds issues
at or above that threshold, which automatically fails the GitHub Actions
step and blocks the workflow. Running `bandit -r . -ll` locally against this
repository's own code returns zero findings.

**What "Shift Left Security" means:** Shift Left Security means moving
security checks earlier in the development lifecycle — into the coding and
pull-request stage — rather than only testing for vulnerabilities after
deployment or during a periodic audit. This workflow implements that
directly: Bandit runs automatically on every push and pull request, so a
Medium or High severity issue is caught and blocks the merge before insecure
code ever reaches the main branch, instead of being discovered later in
production.

---

## 6. Supply Chain Security Statement

A software supply chain attack targets the dependencies a project relies on
rather than the project's own code — for a Python project, this means a
malicious actor compromising one of the open-source packages in
`requirements.txt` (Flask, bcrypt, python-dotenv here), or one of their own
transitive dependencies, so that installing a seemingly trustworthy library
silently pulls in attacker-controlled code. An SBOM (Software Bill of
Materials) is a structured inventory of every component in an application's
full dependency tree — typically listing package names, exact versions,
license information, and often cryptographic hashes — giving a team
visibility into everything actually running, not just what they directly
imported. SCA (Software Composition Analysis) tooling cross-references that
dependency tree against public vulnerability databases such as the National
Vulnerability Database or GitHub's Advisory Database, flagging any package —
direct or several layers deep — with a known CVE that a developer would
likely never check manually. A concrete risk this catches: a compromised or
typosquatted transitive dependency executing arbitrary code at install time
through a malicious `setup.py`, or exfiltrating environment variables and
credentials at runtime.


---

## Repository Contents
- `app.py` — remediated Flask application
- `hash_password.py` — bcrypt password hashing/verification functions
- `requirements.txt` — pinned dependencies
- `.env.example` — required environment variable names, placeholder values only
- `.gitignore` — excludes `.env` and other local artifacts
- `.github/workflows/security.yml` — CI/CD Bandit + Semgrep security gate
