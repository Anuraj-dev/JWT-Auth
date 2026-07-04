# JWT-Auth

A demo authentication system built with Express 5, EJS, and MongoDB, showcasing JWT-based session handling with role-based access control (RBAC).

## Features

- User registration and login with hashed passwords (bcrypt)
- JWT stored in an httpOnly cookie for web session authentication, plus a bearer-token API auth middleware
- Role-based access control (`user` / `admin`)
- Profile view, edit (name/email/password), and account deletion
- Admin dashboard with full user CRUD (create, edit, delete users; admin accounts are protected from deletion/edit via the UI)
- Flash messages for success/error feedback across the app
- Custom error handling with dedicated error views

## Tech stack

- Node.js / Express 5
- EJS + ejs-mate (layouts)
- MongoDB / Mongoose
- jsonwebtoken (JWT)
- bcryptjs (password hashing)
- express-session + connect-flash (flash messages)
- dotenv (environment configuration)

## Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Create a `.env` file in the project root (see `.env.example`):

   ```env
   MONGO_URI=mongodb://localhost:27017/jwt-auth-db
   JWT_SECRET=<a long random string>
   SESSION_SECRET=<a different long random string>
   ADMIN_EMAIL=admin@example.com
   ADMIN_PASSWORD=<a strong password>
   ```

   All of these variables are required — the app and seed script will throw and refuse to start if any are missing.

3. Make sure MongoDB is running and reachable at `MONGO_URI`.

4. (Optional) Seed an initial admin account:

   ```bash
   node seed.js
   ```

5. Start the app:

   ```bash
   node app.js
   ```

   The server listens on port 8000 by default.

## Security note

Earlier commits in this repository's history contained a hardcoded JWT signing secret, a hardcoded session secret, and a hardcoded default admin email/password in `seed.js`. These have since been moved to environment variables, but the old values remain visible in the git history and should be treated as **publicly known**. If this app was ever deployed using those defaults, rotate `JWT_SECRET`, `SESSION_SECRET`, and the admin password immediately, and invalidate any JWTs/sessions issued with the old secret.
