"""
Google OAuth Login (Web App / OpenID Connect)

Requests openid + email + profile to authenticate users via Google.
Built with Flask + Authlib, using Google's OIDC discovery endpoint.

Deployment:
Callback URL: https://googleoauthgetbirthdaygender.vercel.app/callback
Set OAUTH_REDIRECT_URI in .env accordingly.
"""

import json
import os
import secrets

import requests
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import Flask, redirect, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

app = Flask(__name__)

# Behind reverse proxy: trust X-Forwarded-Proto/Host for correct https links
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# Callback URI must exactly match the one registered in Google Console.
# Defaults to localhost:8008 for local dev; override via OAUTH_REDIRECT_URI for production.
REDIRECT_URI = os.environ.get(
    "OAUTH_REDIRECT_URI", "http://localhost:8008/callback"
)

oauth = OAuth(app)
oauth.register(
    name="google",
    client_id=os.environ["GOOGLE_CLIENT_ID"],
    client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    # client_kwargs={"scope": "openid email profile https://www.googleapis.com/auth/user.birthday.read"},
    # client_kwargs={"scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly"},
    client_kwargs={"scope": "openid email profile"},
    # client_kwargs={"scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/documents.readonly https://www.googleapis.com/auth/drive.readonly"},
)

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

STYLE = """
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0f172a; color: #e2e8f0; min-height: 100vh;
  }
  .container { max-width: 720px; margin: 0 auto; padding: 40px 20px; }

  /* --- Login page --- */
  .login-box {
    text-align: center; padding: 80px 20px;
  }
  .login-box h1 { font-size: 2rem; margin-bottom: 8px; color: #f8fafc; }
  .login-box p  { color: #94a3b8; margin-bottom: 32px; }
  .btn {
    display: inline-block; padding: 12px 28px; border-radius: 8px;
    font-size: 15px; font-weight: 600; text-decoration: none;
    transition: transform .15s, box-shadow .15s;
  }
  .btn:hover { transform: translateY(-1px); box-shadow: 0 4px 14px rgba(0,0,0,.4); }
  .btn-google {
    background: #fff; color: #1f2937; margin: 0 8px 12px 0;
  }
  .btn-google svg { vertical-align: middle; margin-right: 8px; }
  .btn-birthday {
    background: linear-gradient(135deg, #f472b6, #a78bfa); color: #fff;
    margin: 0 8px 12px 0;
  }

  /* --- Logged-in header --- */
  .header {
    display: flex; align-items: center; gap: 16px;
    margin-bottom: 32px; padding-bottom: 24px;
    border-bottom: 1px solid #1e293b;
  }
  .header img {
    width: 64px; height: 64px; border-radius: 50%;
    border: 2px solid #334155;
  }
  .header-info h2 { font-size: 1.4rem; color: #f8fafc; }
  .header-info .email { color: #94a3b8; font-size: .9rem; }

  /* --- Highlight cards (Birthday / Gender) --- */
  .highlights {
    display: flex; gap: 16px; margin-bottom: 28px; flex-wrap: wrap;
  }
  .highlight-card {
    flex: 1; min-width: 200px; padding: 20px 24px; border-radius: 12px;
    position: relative; overflow: hidden;
  }
  .highlight-card::before {
    content: ''; position: absolute; inset: 0; opacity: .12;
  }
  .highlight-card .label {
    font-size: .75rem; text-transform: uppercase; letter-spacing: .08em;
    margin-bottom: 6px; font-weight: 600;
  }
  .highlight-card .value { font-size: 1.5rem; font-weight: 700; }
  .card-birthday {
    background: linear-gradient(135deg, rgba(244,114,182,.15), rgba(167,139,250,.15));
    border: 1px solid rgba(244,114,182,.3);
  }
  .card-birthday .label { color: #f472b6; }
  .card-birthday .value { color: #fce7f3; }
  .card-gender {
    background: linear-gradient(135deg, rgba(56,189,248,.15), rgba(99,102,241,.15));
    border: 1px solid rgba(56,189,248,.3);
  }
  .card-gender .label { color: #38bdf8; }
  .card-gender .value { color: #e0f2fe; }

  /* --- Info table --- */
  .section-title {
    font-size: .8rem; text-transform: uppercase; letter-spacing: .08em;
    color: #64748b; margin: 24px 0 10px; font-weight: 600;
  }
  .info-table { width: 100%; border-collapse: collapse; }
  .info-table tr { border-bottom: 1px solid #1e293b; }
  .info-table tr:last-child { border-bottom: none; }
  .info-table td { padding: 10px 12px; vertical-align: top; }
  .info-table .key { color: #94a3b8; font-size: .85rem; white-space: nowrap; width: 160px; }
  .info-table .val { color: #e2e8f0; word-break: break-all; font-size: .9rem; }

  /* --- Actions bar --- */
  .actions { margin: 28px 0; display: flex; gap: 10px; flex-wrap: wrap; }
  .actions a {
    padding: 8px 18px; border-radius: 6px; font-size: .85rem;
    font-weight: 500; text-decoration: none; transition: background .15s;
  }
  .act-primary { background: #1e40af; color: #dbeafe; }
  .act-primary:hover { background: #1d4ed8; }
  .act-secondary { background: #1e293b; color: #94a3b8; }
  .act-secondary:hover { background: #334155; color: #e2e8f0; }
  .act-danger { background: #7f1d1d; color: #fca5a5; }
  .act-danger:hover { background: #991b1b; }
  .refresh-tag {
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: .75rem; font-weight: 600; margin-left: 8px;
  }
  .tag-yes { background: #064e3b; color: #6ee7b7; }
  .tag-no  { background: #78350f; color: #fcd34d; }

  /* --- Raw JSON --- */
  details { margin-top: 20px; }
  details summary {
    cursor: pointer; color: #64748b; font-size: .85rem;
    padding: 8px 0; outline: none;
  }
  details pre {
    background: #1e293b; border-radius: 8px; padding: 16px;
    font-size: .8rem; overflow-x: auto; color: #94a3b8;
    margin-top: 8px; max-height: 400px; overflow-y: auto;
  }

  /* --- People API extra sections --- */
  .extra-section { margin-top: 16px; }
  .extra-section h4 {
    font-size: .85rem; color: #64748b; margin-bottom: 8px;
    text-transform: uppercase; letter-spacing: .05em;
  }
  .pill {
    display: inline-block; padding: 4px 12px; margin: 3px 4px 3px 0;
    background: #1e293b; border-radius: 20px; font-size: .82rem; color: #cbd5e1;
  }
</style>
"""

GOOGLE_SVG = (
    '<svg width="18" height="18" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>'
    '<path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>'
    '<path fill="#FBBC05" d="M10.53 28.59a14.5 14.5 0 010-9.18l-7.98-6.19a24.0 24.0 0 000 21.56l7.98-6.19z"/>'
    '<path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>'
    '<path fill="none" d="M0 0h48v48H0z"/></svg>'
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_birthday(user: dict) -> str | None:
    """Try to pull a human-readable birthday from People API data."""
    for b in user.get("birthdays", []):
        d = b.get("date", {})
        y, m, day = d.get("year"), d.get("month"), d.get("day")
        if m and day:
            return f"{y}-{m:02d}-{day:02d}" if y else f"{m:02d}-{day:02d}"
    return None


def _extract_gender(user: dict) -> str | None:
    """Try to pull gender value from People API data."""
    for g in user.get("genders", []):
        v = g.get("formattedValue") or g.get("value")
        if v:
            return v
    return None


def _info_row(key: str, val) -> str:
    return (
        f"<tr><td class='key'>{key}</td>"
        f"<td class='val'>{val}</td></tr>"
    )


def _build_page(user: dict) -> str:
    """Render the full logged-in page as an HTML string."""
    pic = user.get("picture", "")
    name = user.get("name", "Unknown")
    email = user.get("email", "")
    photo_html = f"<img src='{pic}' alt='avatar'>" if pic else ""

    # --- highlight cards ---
    birthday = _extract_birthday(user)
    gender = _extract_gender(user)
    cards_html = ""
    if birthday or gender:
        cards_html = '<div class="highlights">'
        if birthday:
            cards_html += (
                '<div class="highlight-card card-birthday">'
                '<div class="label">Birthday</div>'
                f'<div class="value">{birthday}</div></div>'
            )
        if gender:
            cards_html += (
                '<div class="highlight-card card-gender">'
                '<div class="label">Gender</div>'
                f'<div class="value">{gender}</div></div>'
            )
        cards_html += "</div>"

    # --- basic info table ---
    rows = ""
    for k in ("sub", "email", "email_verified", "name", "given_name",
              "family_name", "locale", "picture"):
        v = user.get(k)
        if v is not None:
            if k == "picture":
                v = f"<img src='{v}' style='height:32px;border-radius:4px'>"
            rows += _info_row(k, v)

    # --- People API extras ---
    extras_html = ""
    people_fields = [
        ("addresses", "Addresses"),
        ("phoneNumbers", "Phone Numbers"),
        ("locales", "Locales"),
        ("nicknames", "Nicknames"),
        ("organizations", "Organizations"),
    ]
    for field, title in people_fields:
        items = user.get(field)
        if items:
            pills = ""
            for item in items:
                if field == "addresses":
                    text = item.get("formattedValue", "")
                elif field == "organizations":
                    name_ = item.get("name", "")
                    title_ = item.get("title", "")
                    text = f"{name_} — {title_}" if title_ else name_
                else:
                    text = item.get("formattedValue") or item.get("value", "")
                if text:
                    pills += f"<span class='pill'>{text}</span>"
            if pills:
                extras_html += (
                    f"<div class='extra-section'><h4>{title}</h4>{pills}</div>"
                )

    # --- refresh token tag ---
    has_rt = bool(session.get("refresh_token"))
    rt_tag = (
        "<span class='refresh-tag tag-yes'>Yes</span>" if has_rt
        else "<span class='refresh-tag tag-no'>No</span>"
    )

    # --- raw json ---
    raw = json.dumps(user, indent=2, ensure_ascii=False)

    return (
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Google OAuth</title>"
        f"{STYLE}"
        "</head><body><div class='container'>"
        # header
        "<div class='header'>"
        f"{photo_html}"
        "<div class='header-info'>"
        f"<h2>{name}</h2>"
        f"<div class='email'>{email}</div>"
        "</div></div>"
        # highlights
        f"{cards_html}"
        # actions
        "<div class='actions'>"
        "<a class='act-primary' href='/refresh'>Refresh Profile</a>"
        "<a class='act-secondary' href='/gmail'>Gmail</a>"
        "<a class='act-secondary' href='/gdocs'>Google Docs</a>"
        "<a class='act-danger' href='/logout'>Logout</a>"
        f" Refresh Token: {rt_tag}"
        "</div>"
        # user info table
        "<div class='section-title'>User Info</div>"
        f"<table class='info-table'>{rows}</table>"
        # people api extras
        f"{extras_html}"
        # error
        (f"<div class='extra-section' style='color:#f87171'>"
         f"<b>People API Error:</b> {user['_people_api_error']}</div>")
        if "_people_api_error" in user else ""
        # raw json
        "<details><summary>View Raw JSON</summary>"
        f"<pre>{raw}</pre></details>"
        "</div></body></html>"
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    user = session.get("user")
    if user:
        return _build_page(user)
    return (
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Google OAuth</title>"
        f"{STYLE}"
        "</head><body><div class='container'><div class='login-box'>"
        "<h1>Google OAuth</h1>"
        "<p>Sign in with your Google account to continue</p>"
        f"<a class='btn btn-google' href='/login'>{GOOGLE_SVG} Sign in with Google</a>"
        "<br>"
        "<a class='btn btn-birthday' href='/login_full'>Sign in with Birthday scope</a>"
        "</div></div></body></html>"
    )


@app.route("/login")
def login():
    # access_type=offline -> Google returns a refresh_token
    return oauth.google.authorize_redirect(REDIRECT_URI, access_type="offline")


@app.route("/login_full")
def login_full():
    # Same as /login but with extra scopes (e.g. birthday)
    return oauth.google.authorize_redirect(
        REDIRECT_URI,
        access_type="offline",
        scope="openid email profile https://www.googleapis.com/auth/user.birthday.read",
    )


@app.route("/callback")
def auth_callback():
    token = oauth.google.authorize_access_token()
    user = token.get("userinfo")
    if not user:
        user = oauth.google.userinfo(token=token)
    user = dict(user)

    # People API: fetch birthday, gender, address, etc. (not in OIDC /userinfo)
    access_token = token.get("access_token")
    if access_token:
        try:
            resp = requests.get(
                "https://people.googleapis.com/v1/people/me",
                params={"personFields": "birthdays,genders,addresses,phoneNumbers,locales,nicknames,organizations"},
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
            if resp.ok:
                people = resp.json()
                for key in ("birthdays", "genders", "addresses", "phoneNumbers", "locales", "nicknames", "organizations"):
                    if key in people:
                        user[key] = people[key]
                user["_people_api_raw"] = people
            else:
                user["_people_api_error"] = f"{resp.status_code}: {resp.text}"
        except Exception as e:
            user["_people_api_error"] = str(e)

    # Debug: print token keys
    print("\n--- RAW TOKEN KEYS ---")
    print(sorted(token.keys()))
    for k, v in token.items():
        if "refresh" in str(k).lower() or "refresh" in str(v)[:50].lower() if isinstance(v, str) else False:
            print(f">>> refresh-related: {k}")

    # Save refresh_token to session
    if token.get("refresh_token"):
        session["refresh_token"] = token["refresh_token"]
        print(">>> refresh_token SAVED to session")
    else:
        print(">>> refresh_token NOT FOUND in token response")

    session["user"] = user
    print("\n" + "=" * 60)
    print("GOOGLE USER INFO (full)")
    print("=" * 60)
    print(json.dumps(user, indent=2, ensure_ascii=False))
    print("=" * 60 + "\n")
    return redirect("/")


@app.route("/refresh")
def refresh():
    """Exchange refresh_token for a new access_token and re-fetch user info."""
    rt = session.get("refresh_token")
    if not rt:
        return "No refresh_token. Please <a href='/login'>login</a> again."
    token_resp = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "refresh_token": rt,
            "grant_type": "refresh_token",
        },
        timeout=10,
    )
    if not token_resp.ok:
        return f"Refresh failed: {token_resp.status_code} {token_resp.text}<br><a href='/'>Back</a>"
    token_data = token_resp.json()
    access_token = token_data["access_token"]

    # Fetch userinfo
    userinfo_resp = requests.get(
        "https://openidconnect.googleapis.com/v1/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    user = dict(userinfo_resp.json()) if userinfo_resp.ok else {}

    # People API
    try:
        resp = requests.get(
            "https://people.googleapis.com/v1/people/me",
            params={"personFields": "birthdays,genders,addresses,phoneNumbers,locales,nicknames,organizations"},
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        if resp.ok:
            people = resp.json()
            for key in ("birthdays", "genders", "addresses", "phoneNumbers", "locales", "nicknames", "organizations"):
                if key in people:
                    user[key] = people[key]
            user["_people_api_raw"] = people
        else:
            user["_people_api_error"] = f"{resp.status_code}: {resp.text}"
    except Exception as e:
        user["_people_api_error"] = str(e)

    session["user"] = user
    print("\n" + "=" * 60)
    print("REFRESHED USER INFO")
    print("=" * 60)
    print(json.dumps(user, indent=2, ensure_ascii=False))
    print("=" * 60 + "\n")
    return redirect("/")


def _api_err(resp):
    """Extract API error into formatted HTML, or empty string if OK."""
    if resp.ok:
        return ""
    try:
        err = resp.json().get("error", {})
        msg = err.get("message", resp.text)
        code = err.get("code", resp.status_code)
        reason = err.get("errors", [{}])[0].get("reason", "")
    except Exception:
        msg, code, reason = resp.text, resp.status_code, ""
    return (
        f"<div style='background:#7f1d1d;border:1px solid #991b1b;padding:12px;margin:12px 0;border-radius:8px;color:#fca5a5'>"
        f"<b>API Error [{code}]</b><br>{msg}"
        f"{f'<br><small>reason: {reason}</small>' if reason else ''}"
        f"</div>"
    )


def _page_wrap(title: str, body: str) -> str:
    return (
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{title}</title>"
        f"{STYLE}"
        f"</head><body><div class='container'>{body}</div></body></html>"
    )


@app.route("/gmail")
def gmail():
    """Fetch recent emails via Gmail API."""
    access_token = _get_access_token()
    if not access_token:
        return _page_wrap("Gmail", "Cannot get access_token. Please <a href='/login' style='color:#60a5fa'>login</a> first.")
    headers = {"Authorization": f"Bearer {access_token}"}
    errors = ""

    # 1. List labels
    labels_resp = requests.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/labels",
        headers=headers, timeout=10,
    )
    errors += _api_err(labels_resp)
    labels = labels_resp.json().get("labels", []) if labels_resp.ok else []

    # 2. Fetch last 10 messages
    msgs_resp = requests.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
        params={"maxResults": 10},
        headers=headers, timeout=10,
    )
    errors += _api_err(msgs_resp)
    messages = []
    if msgs_resp.ok:
        for msg in msgs_resp.json().get("messages", []):
            detail = requests.get(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg['id']}",
                params={"format": "metadata", "metadataHeaders": "Subject,From,Date"},
                headers=headers, timeout=10,
            )
            if detail.ok:
                d = detail.json()
                headers_map = {h["name"]: h["value"] for h in d.get("payload", {}).get("headers", [])}
                messages.append({
                    "id": msg["id"],
                    "subject": headers_map.get("Subject", "(no subject)"),
                    "from": headers_map.get("From", "(unknown)"),
                    "date": headers_map.get("Date", ""),
                    "snippet": d.get("snippet", ""),
                })

    label_html = "".join(f"<span class='pill'>{l['name']}</span>" for l in labels)
    msg_rows = ""
    for m in messages:
        msg_rows += (
            f"<tr>"
            f"<td class='val' style='white-space:nowrap'>{m['date']}</td>"
            f"<td class='val'>{m['from']}</td>"
            f"<td class='val'><b>{m['subject']}</b><br>"
            f"<small style='color:#64748b'>{m['snippet']}</small></td></tr>"
        )
    body = (
        "<a class='act-secondary' href='/' style='margin-bottom:20px;display:inline-block'>← Back</a>"
        "<h2 style='margin-bottom:16px'>Gmail</h2>"
        f"{errors}"
        f"<div class='section-title'>Labels ({len(labels)})</div>"
        f"<div style='margin-bottom:16px'>{label_html}</div>"
        f"<div class='section-title'>Recent {len(messages)} Messages</div>"
        f"<table class='info-table'>{msg_rows}</table>"
    )
    return _page_wrap("Gmail", body)


def _get_access_token():
    """Exchange refresh_token for a new access_token. Returns None on failure."""
    rt = session.get("refresh_token")
    if not rt:
        return None
    resp = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "refresh_token": rt,
            "grant_type": "refresh_token",
        },
        timeout=10,
    )
    return resp.json().get("access_token") if resp.ok else None


@app.route("/gdocs")
def gdocs():
    """List recent Google Docs via Drive API."""
    access_token = _get_access_token()
    if not access_token:
        return _page_wrap("Google Docs", "Cannot get access_token. Please <a href='/login' style='color:#60a5fa'>login</a> first.")
    headers = {"Authorization": f"Bearer {access_token}"}

    drive_resp = requests.get(
        "https://www.googleapis.com/drive/v3/files",
        params={
            "q": "mimeType='application/vnd.google-apps.document'",
            "fields": "files(id,name,createdTime,modifiedTime,owners)",
            "orderBy": "modifiedTime desc",
            "pageSize": 20,
        },
        headers=headers, timeout=10,
    )
    errors = _api_err(drive_resp)
    files = drive_resp.json().get("files", []) if drive_resp.ok else []

    doc_rows = ""
    for f in files:
        owner = f.get("owners", [{}])[0].get("displayName", "?")
        doc_rows += (
            f"<tr>"
            f"<td class='val'><a href='https://docs.google.com/document/d/{f['id']}/edit' target='_blank' style='color:#60a5fa'>{f['name']}</a></td>"
            f"<td class='val'>{owner}</td>"
            f"<td class='val' style='white-space:nowrap'>{f.get('createdTime','')}</td>"
            f"<td class='val' style='white-space:nowrap'>{f.get('modifiedTime','')}</td>"
            f"</tr>"
        )

    body = (
        "<a class='act-secondary' href='/' style='margin-bottom:20px;display:inline-block'>← Back</a>"
        "<h2 style='margin-bottom:16px'>Google Docs</h2>"
        f"{errors}"
        f"<div class='section-title'>Recent {len(files)} Documents</div>"
        f"<table class='info-table'>"
        f"<tr><td class='key'>Title</td><td class='key'>Owner</td>"
        f"<td class='key'>Created</td><td class='key'>Modified</td></tr>"
        f"{doc_rows}</table>"
    )
    return _page_wrap("Google Docs", body)


@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("refresh_token", None)
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8008, debug=True)
