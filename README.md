# HPF Family Website V4 — Offline-friendly

This version embeds the CSS and HPF logo directly into each HTML page so it can render correctly when opened from Android file managers/content:// URLs.

Open `index.html` in Chrome. The homepage should display with the full HPF design even if the file manager blocks linked CSS/image files.

## General Secretary contact
WhatsApp: 09164958696. Executive-service interest, hostel prayer fellowship setup, and HPF enquiries are directed to the General Secretary.

## V6
Added `serve.html` for executive service interest and Hostel Prayer Fellowship altar requests, with direct WhatsApp follow-up to the General Secretary at 09164958696.

## HPF Spiritual Growth App
The website now promotes the updated HPF app at https://incredible-gecko-e48a13.netlify.app/ and provides an Open HPF App call-to-action.

## V8 Member System
Added member.html for HPF member profile creation and a member-home experience linking to the Spiritual Growth App and HPF service pathways.

## V9 Live Member Backend
Added Flask + SQLite endpoints for member profiles and executive/hostel applications. The static pages gracefully fall back to local storage/WhatsApp when the backend is not running.
Run locally with Python 3.10+: `python -m venv .venv`, activate, `pip install -r requirements.txt`, then `python app.py`.
For production, add authentication/authorization to admin endpoints, HTTPS, CSRF protection, rate limiting, secure secrets, backups and PostgreSQL.

## V10 Secure Accounts
Added registration and login with PBKDF2 password hashing, persistent Flask sessions, logout, and member identity endpoints. Passwords are never stored in plain text.
IMPORTANT: admin endpoints still need real admin authentication before production deployment.

## V11 Member Dashboard
Added authenticated member dashboard connected to `/api/me`, with spiritual growth app, profile, fellowship, discipleship, programs, service, prayer/testimony and General Secretary pathways.

## V12 Complete Platform
Added leadership/admin dashboard, announcements, programs, prayer requests, testimonies, protected admin API, member dashboard community modules, and deployment files.

## V13 Production Ready
Fixed the testimony persistence bug and added production secret enforcement, secure session-cookie settings, health endpoint, controlled admin bootstrap command, Gunicorn configuration, PostgreSQL deployment guidance and launch checklist.

## V14 Free Hosting
Added Render Blueprint (`render.yaml`) and a free-hosting deployment guide. The service can receive a public `onrender.com` address before HPF buys a custom domain.
