# HPF Family — Production Deployment

## Recommended production stack
- Web: Render/Railway/Fly.io/VPS
- Database: managed PostgreSQL
- HTTPS: platform-managed TLS
- Runtime: Python 3.11+
- Server: Gunicorn

## Environment
Set:
- `FLASK_ENV=production`
- `HPF_SECRET_KEY` to a long random value
- `DATABASE_URL` to the managed PostgreSQL connection string
- `COOKIE_SECURE=1`

## First administrator
Run once on the deployed service:
`python app.py create-admin --name "HPF Admin" --phone "..." --password "..." --email "..."`

Use a unique password of at least 12 characters. Do not put the password in source control.

## Launch
`pip install -r requirements.txt`
`gunicorn app:app --workers 2 --timeout 120`

## Domain
Point the HPF domain's DNS to the hosting provider, enable HTTPS, and test:
- `/`
- `/member.html`
- `/login.html`
- `/dashboard.html`
- `/admin.html`
- `/health`

## Before public launch
1. Use PostgreSQL, not SQLite.
2. Confirm admin authentication works.
3. Enable HTTPS and secure cookies.
4. Configure automated database backups.
5. Add rate limiting/WAF at the hosting layer.
6. Review privacy/consent language for member data.
7. Test registration, login, logout, prayer requests, testimonies, applications, announcements and programs.
