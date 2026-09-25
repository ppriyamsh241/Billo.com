# Billo API + PostgreSQL

The repository now includes a PostgreSQL-backed Billo API for shared merchant and
administrator data.

## Database

The schema is in `database/schema.sql`. It creates:

- administrators and merchant accounts
- merchant settings
- products and customers
- invoices and invoice items
- transactions
- subscription plans and subscription payments
- voucher-file metadata
- administrator audit logs

The default subscription plans are seeded as 1 month (Rs 200), 3 months (Rs 500),
and 12 months (Rs 2000).

## Run locally with Docker

1. Set a strong `POSTGRES_PASSWORD` and `JWT_SECRET` in your shell/environment.
2. Run:

```bash
docker compose up -d --build
```

3. Check:

`http://localhost:3000/health`

The PostgreSQL data is persisted in the `billo_postgres` Docker volume and voucher
files are persisted in `billo_vouchers`.

## Run without Docker

Install PostgreSQL, create a database named `billo`, then set:

```
DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/billo
JWT_SECRET=your-long-random-secret
ALLOWED_ORIGINS=https://billo.com,https://www.billo.com
PORT=3000
```

Then:

```bash
cd server
npm install
npm start
```

The server automatically loads `database/schema.sql` before listening.

## First administrator

When no administrator exists, call `POST /api/setup/admin` with a name, email,
and password of at least 10 characters. The route is permanently disabled after
the first administrator is created.

## Important deployment note

GitHub stores the code; GitHub Pages does **not** run the Node.js API or provide a
persistent PostgreSQL database. For billo.com to use this shared database in
production, deploy the Dockerized API and PostgreSQL on a server/database host
(or a managed PostgreSQL service), then point the website's API configuration at
the API's HTTPS URL.

Never commit `.env`, database passwords, JWT secrets, bank credentials, or other
private credentials to the repository. Never expose PostgreSQL directly to the
public internet.
