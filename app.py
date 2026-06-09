"""
Google OAuth Login (Web App / OpenID Connect)

Requests openid + email + profile to authenticate users via Google.
Built with Flask + Authlib, using Google's OIDC discovery endpoint.

Deployment:
Reverse proxy maps https://googleoauthgetbirthdaygender.vercel.app/auth/ to this app's root path /.
Callback URL: https://googleoauthgetbirthdaygender.vercel.app/auth/callback
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


class PrefixMiddleware:
    """Detect reverse-proxy mount prefix (e.g. /auth) via X-Forwarded-Prefix.

    Requires nginx: proxy_set_header X-Forwarded-Prefix /auth;
    """

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        prefix = environ.get("HTTP_X_FORWARDED_PREFIX", "").rstrip("/")
        if prefix:
            environ["SCRIPT_NAME"] = prefix
        return self.wsgi_app(environ, start_response)


# Behind reverse proxy: trust X-Forwarded-Proto/Host for correct https links,
# and apply X-Forwarded-Prefix for /auth mount
app.wsgi_app = PrefixMiddleware(ProxyFix(app.wsgi_app, x_proto=1, x_host=1))
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

def _html_table(data: dict) -> str:
    rows = "".join(
        f"<tr><td style='padding:4px 12px;font-weight:bold'>{k}</td>"
        f"<td style='padding:4px 12px;word-break:break-all'>{v}</td></tr>"
        for k, v in sorted(data.items())
    )
    return f"<table border='1' cellpadding='0' cellspacing='0' style='border-collapse:collapse'>{rows}</table>"


@app.route("/")
def index():
    user = session.get("user")
    if user:
        pic = user.get("picture", "")
        photo_html = f"<img src='{pic}' width='80' style='border-radius:50%'>" if pic else ""
        table = _html_table(user)
        raw = json.dumps(user, indent=2, ensure_ascii=False)
        has_refresh = "Yes" if session.get("refresh_token") else "No (login again to get one)"
        return (
            f"<h2>Logged In</h2>{photo_html}<br><br>"
            f"<a href='logout'>Logout</a> | "
            f"<a href='refresh'>Refresh Profile</a> | "
            f"<a href='gmail'>Gmail</a> | "
            f"<a href='gdocs'>Google Docs</a> | "
            f"<a href='https://myaccount.google.com/u/0/connections' target='_blank'>Revoke Access</a><br><br>"
            f"<b>Refresh Token:</b> {has_refresh}<br><br>"
            f"<h3>User Info (Full)</h3>{table}"
            f"<h3>Raw JSON</h3><pre>{raw}</pre>"
        )
    return (
        "<h2>Not Logged In</h2>"
        "<a href='login'>Sign in with Google</a><br><br>"
        "<a href='login_full'>Sign in with Google (Birthday)</a>"
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
    return redirect("./")


@app.route("/refresh")
def refresh():
    """Exchange refresh_token for a new access_token and re-fetch user info."""
    rt = session.get("refresh_token")
    if not rt:
        return "No refresh_token. Please <a href='login'>login</a> again."
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
        return f"Refresh failed: {token_resp.status_code} {token_resp.text}<br><a href='./'>Back</a>"
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
    return redirect("./")


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
        f"<div style='background:#fff3f3;border:1px solid #f00;padding:10px;margin:10px 0;border-radius:4px'>"
        f"<b>API Error [{code}]</b><br>{msg}"
        f"{f'<br><small>reason: {reason}</small>' if reason else ''}"
        f"</div>"
    )


@app.route("/gmail")
def gmail():
    """Fetch recent emails via Gmail API."""
    access_token = _get_access_token()
    if not access_token:
        return "Cannot get access_token. Please <a href='login'>login</a> first."
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

    label_html = "".join(f"<li>{l['name']}</li>" for l in labels)
    msg_rows = "".join(
        f"<tr><td style='padding:4px 8px'>{m['date']}</td>"
        f"<td style='padding:4px 8px'>{m['from']}</td>"
        f"<td style='padding:4px 8px'><b>{m['subject']}</b><br>"
        f"<small style='color:#888'>{m['snippet']}</small></td></tr>"
        for m in messages
    )
    return (
        "<h2>Gmail</h2><a href='./'>Back</a>"
        f"{errors}"
        f"<h3>Labels ({len(labels)})</h3><ul>{label_html}</ul>"
        f"<h3>Recent {len(messages)} Messages</h3>"
        f"<table border='1' cellpadding='0' cellspacing='0' style='border-collapse:collapse;width:100%'>"
        f"<tr style='background:#f0f0f0'><th>Date</th><th>From</th><th>Subject / Snippet</th></tr>"
        f"{msg_rows}</table>"
    )


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
        return "Cannot get access_token. Please <a href='login'>login</a> first."
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
            f"<td style='padding:4px 8px'><a href='https://docs.google.com/document/d/{f['id']}/edit' target='_blank'>{f['name']}</a></td>"
            f"<td style='padding:4px 8px'>{owner}</td>"
            f"<td style='padding:4px 8px'>{f.get('createdTime','')}</td>"
            f"<td style='padding:4px 8px'>{f.get('modifiedTime','')}</td>"
            f"</tr>"
        )

    return (
        "<h2>Google Docs</h2><a href='./'>Back</a>"
        f"{errors}"
        f"<h3>Recent {len(files)} Documents</h3>"
        f"<table border='1' cellpadding='0' cellspacing='0' style='border-collapse:collapse;width:100%'>"
        f"<tr style='background:#f0f0f0'><th>Title</th><th>Owner</th><th>Created</th><th>Modified</th></tr>"
        f"{doc_rows}</table>"
    )


@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("refresh_token", None)
    return redirect("./")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8008, debug=True)
