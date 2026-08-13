# Put HPF Family online without buying a domain

We prepared this project for Render.

Render can deploy a Flask web service from GitHub and gives the service a public `onrender.com` URL. The official Flask deployment guide uses:
- Build: `pip install -r requirements.txt`
- Start: `gunicorn app:app`

## You still need
1. A GitHub account.
2. A Render account.
3. Upload this project to a GitHub repository.
4. Connect the repository to Render and create the web service.
5. Render will provide the public URL.

## Important database note
The current code has SQLite for development. Free web hosting may use ephemeral storage, so do not rely on SQLite for permanent member records in production. Move the member/application data to managed PostgreSQL before collecting real member information.

## After deployment
Create the first administrator with:
`python app.py create-admin --name "HPF Admin" --phone "..." --password "..."`

Then test:
- `/`
- `/member.html`
- `/login.html`
- `/dashboard.html`
- `/admin.html`
- `/health`

Later, a custom HPF domain can be connected to the same Render service.
