# Google OAuth — People API Birthday & Gender Leak

A proof-of-concept demonstrating how the Google People API exposes users' birthday and gender to third-party OAuth applications — even when users believe this information is private.

## The Vulnerability

When a user sets their birthday and gender visibility to **"Anyone"** (public) in their Google Account settings, they expect this information to appear only on Google's own services. [Google's own documentation](https://support.google.com/accounts/answer/6304920#zippy=%2Cwhere-this-info-can-show-up%2Cwho-can-view-your-info:~:text=Info%20in%20your,Play%2C%20and%20YouTube.) states:

> **Where this info can show up**
> Info in your Google Account that you make visible to Anyone can be found in a few places:
> - On Google services where you can contact other people, like Google Chat and Gmail.
> - On Google services where you create content, like Maps, Play, and YouTube.

This implies that "public" birthday and gender are scoped to **Google's own services only**. However, that is not the case.

### How It Works

1. A developer creates a standard Google OAuth 2.0 app.
2. In the Google Cloud Console, the developer enables the **People API**.
3. The app requests the scopes `user.birthday.read` and `user.gender.read`.
4. When a user whose birthday/gender is set to **"Anyone"** logs in, the app calls `people.googleapis.com/v1/people/me` and retrieves their birthday and gender — **without any additional consent prompt**.

The user sees a normal "Sign in with Google" flow (openid / email / profile). The extra People API scopes (`user.birthday.read`, `user.gender.read`) are bundled in silently. There is no indication to the user that their birthday or gender will be accessed.

### What's Exposed

The People API returns structured data:

```json
{
  "birthdays": [{ "date": { "year": 1990, "month": 6, "day": 11 } }],
  "genders": [{ "value": "Male" }]
}
```

## PoC

Live demo: **https://googleoauthgetbirthdaygender.vercel.app**

1. Click **"Sign in with Birthday & Gender scope"**.
2. Authorize the app with your Google account.
3. If your birthday/gender is set to "Anyone", the app displays them immediately.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env   # Fill in GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
python app.py
```

Open http://localhost:8008.

### Google Cloud Console Configuration

In [Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials), edit your OAuth 2.0 client.
The **Authorized redirect URIs** must match exactly:

| Environment | Redirect URI |
|-------------|-------------|
| Local dev   | `http://localhost:8008/callback` |
| Production  | `https://googleoauthgetbirthdaygender.vercel.app/callback` |

Also enable the **People API** under [APIs & Services → Library](https://console.cloud.google.com/apis/library/people.googleapis.com).

## Files

- `app.py` — All logic (login / callback / People API call / UI)
- `api/index.py` — Vercel serverless entry point
- `.env` — Credentials (ignored by .gitignore, do not commit)
