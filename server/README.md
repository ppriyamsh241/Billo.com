# Billo local server

This API uses the local PostgreSQL database named `billo`. It supplies role-based
access to the merchant and admin data, as well as private voucher file storage.

## Start it

1. Copy `.env.example` to `.env` and set `JWT_SECRET` to a long random value
   before allowing any network access.
2. Run `npm install`.
3. Run `npm start`.
4. Visit `http://localhost:3000/health`.

## First admin

When no administrator exists, call `POST /api/setup/admin` with a name, email,
and password. The route is permanently disabled after the first administrator
account is created.

## Important

GitHub Pages is HTTPS. A browser will block a call from the published Pages site
to an ordinary `http://` API on this laptop. For use beyond this computer, put
the API behind an HTTPS reverse proxy or secure tunnel, and then set its public
HTTPS URL in the website configuration. Do not expose PostgreSQL directly.

