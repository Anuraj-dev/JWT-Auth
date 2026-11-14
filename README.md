<h1 align="center">JWT-Auth</h1>

<p align="center">
  A sign-in demo for Express 5 and MongoDB, with JWT sessions and an admin role.<br />
  Users manage their own profile. Admins manage regular users from one dashboard.
</p>

JWT-Auth shows how a small web app can keep people signed in with JSON Web Tokens. Visitors register, log in, change their name, email or password, or delete their account. Admins get a dashboard that lists every user and lets them create, edit or delete regular users.

The server renders its pages with EJS and stores users in MongoDB through Mongoose. It listens on port 8000. You provide the database URL and two secrets in a `.env` file. No third-party accounts or API keys are needed.

## What you get

- **Sign-in in an httpOnly cookie.** Login signs a JWT with `JWT_SECRET` that expires after 7 days and stores it in a `token` cookie that page scripts cannot read. Every protected route verifies that cookie before it renders.
- **Passwords stored as bcrypt hashes.** A Mongoose pre-save hook hashes each new or changed password with bcryptjs and a salt of 10 rounds. Sign-up, profile changes and the admin forms reject passwords shorter than 6 characters.
- **Two roles checked on the server.** Each user is either `user` or `admin`, and the role is stored in the token. Every `/admin` route passes through an `authorizeAdmin` check that sends everyone else back to the home page.
- **User management for admins.** The dashboard lists every user without password hashes. Admins create users with a chosen role, edit regular users' name, email, role or password, and delete them. Admin accounts can't be edited or deleted from the dashboard.
- **A profile page for every user.** Users see their details, change their name, email or password, and delete their account. A password change needs the current password. Admin accounts can't delete themselves.
- **Real PUT and DELETE from HTML forms.** Forms send a POST with `?_method=PUT` or `?_method=DELETE`, and method-override turns the request into that verb.
- **Flash messages for every result.** Each action redirects with a success or error message, shown on the next page.

## Running it

You need Node.js 18 or newer and a MongoDB server that `MONGO_URI` can reach. Run every command from the project root, because dotenv reads `.env` from the current directory.

### Install dependencies

```sh
npm install
```

### Create the `.env` file

```sh
cp .env.example .env
```

Replace each placeholder value. [Configuration](#configuration) lists what each variable does.

### Create the first admin

`seed.js` creates one admin account from `ADMIN_EMAIL` and `ADMIN_PASSWORD`. It does nothing if an admin already exists.

```sh
node seed.js
```

The script loads `app.js`, so it also starts the web server, and the process keeps running. Stop it with Ctrl+C before you start the app. The script prints the admin password, so change it after your first login.

### Start the app

```sh
node app.js
```

Open http://localhost:8000. After you log in, admins land on `/admin/dashboard` and other users land on `/profile`.

## Configuration

The app refuses to start if `MONGO_URI`, `JWT_SECRET` or `SESSION_SECRET` is missing. The seed script refuses to run without `MONGO_URI`, `ADMIN_EMAIL` or `ADMIN_PASSWORD`.

| Variable | Read by | Purpose |
| --- | --- | --- |
| `MONGO_URI` | app, seed | MongoDB connection string, for example `mongodb://localhost:27017/jwt-auth-db`. |
| `JWT_SECRET` | app | Signs login tokens. Use a long random string. |
| `SESSION_SECRET` | app | Signs the express-session cookie. Use a different random string. |
| `ADMIN_EMAIL` | seed | Email for the admin account that `seed.js` creates. |
| `ADMIN_PASSWORD` | seed | Password for that admin account. Use a strong one. |

To generate a secret:

```sh
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

The port is fixed at 8000. To change it, edit `app.listen(8000)` in `app.js`.

## How it works

Login checks the password with `bcrypt.compare`. On success, the server signs a token that holds the user's id, name, email and role, and sends it back in the `token` cookie.

Each request reads that cookie and checks its signature and expiry. The role comes from the token, so the admin checks don't query the database.

That has a consequence. A role change applies the next time that user logs in or saves their own profile. A demoted admin keeps dashboard access until the old token expires, up to 7 days.

Flash messages live in the session. express-session uses its default in-memory store, so sessions don't survive a restart.

## Security

- Earlier commits had a hardcoded JWT secret, a hardcoded session secret and a seed admin password of `admin123`. Commit `82a0428` moved them into environment variables, but the old values stay in the git history, so treat them as public. If you ran an earlier version with those defaults, rotate `JWT_SECRET`, `SESSION_SECRET` and the admin password. Changing `JWT_SECRET` signs out everyone who holds a token.
- `POST /register` accepts a `role` field, so anyone can register an admin account. Remove that field from the handler before you run the app anywhere other than your own machine.
- The token and session cookies are not marked `Secure`. Set `secure: true` in `app.js` when you serve the app over HTTPS.

## License

MIT. See [LICENSE](LICENSE).
