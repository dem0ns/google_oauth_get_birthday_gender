# Google OAuth Login (Web / OpenID Connect)

Sign in with Google using Flask + Authlib. Requests `openid email profile`, retrieves user identity (name / email / picture) after login.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env   # Fill in GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
python app.py
```

Open http://localhost:8008 and click "Sign in with Google".

## Google Cloud Console Configuration (Important)

In [Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials), edit your OAuth 2.0 client.
The **Authorized redirect URIs** must exactly match the callback path in your code:

| Environment | Redirect URI to Add |
|-------------|---------------------|
| Local dev   | `http://localhost:8008/auth/callback` |
| Production  | `https://googleoauthgetbirthdaygender.vercel.app/auth/callback` |

> If the registered URI does not include `/auth/callback`, you will get a `redirect_uri_mismatch` error.
> Either update the callback path in code or add the URIs above in the Console.

## Files

- `app.py` — All logic (login / callback / logout)
- `.env` — Credentials (ignored by .gitignore, do not commit)
