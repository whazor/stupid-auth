# stupid-auth

`stupid-auth` is a small forward-auth service for homelabs.

It is built for simple operations:
- users in a YAML file
- sessions in memory
- no external database

## What It Does

- `GET /login` + `POST /login` for username/password login
- `POST /login/start` + `POST /login/finish` for passkey login
- `GET /auth` for forward-auth checks (`401` or `Remote-User` header)
- `GET /logout` to clear auth session
- `GET /tutorial` to generate/bootstrap config

## Quick Start

1. Run `stupid-auth` behind HTTPS on `auth.<your-domain>`.
2. Set `AUTH_DOMAIN` to your cookie domain (for example `nanne.casa`).
3. Mount `users.yaml` and point `AUTH_CONFIG_FILE` to it.
4. Open `/tutorial` and create your initial config.
5. Configure your reverse proxy/app ingress to call `/auth` for protected routes.

## Minimal Runtime Config

Required in practice:
- `AUTH_DOMAIN`
- `AUTH_CONFIG_FILE`

Typical env:

```bash
AUTH_ADDRESS=0.0.0.0
AUTH_PORT=8000
AUTH_DOMAIN=nanne.casa
AUTH_COOKIE_EXPIRE=30
AUTH_CONFIG_FILE=/users.yaml
```

## users.yaml Format

You can run password-only, passkey-only, or mixed.

Example:

```yaml
server_signing_key: "replace-with-random-64-char-secret"
users:
  - username: foo
    password: "$argon2id$..."
passkeys:
  - username: foo
    credential_id: "..."
    raw_id: "..."
    client_data_json: "..."
    attestation_object: "..."
    public_key_cose: "..."
    sign_count: 1
    signature: "..."
```

Notes:
- `users` controls password login availability.
- `passkeys` controls passkey login availability.
- If both lists are empty, login page shows a link to `/tutorial`.

## Login Behavior

- If only password users exist: password form is shown.
- If only passkeys exist: passkey button is shown.
- If both exist: both methods are shown.
- Redirect URL (`rd`) is validated:
  - allowed: relative paths (`/app`) or absolute URLs on `AUTH_DOMAIN` / subdomains
  - rejected: other domains (for example `badexample.com` when domain is `example.com`)

## Forward Auth Integration

Expected check endpoint:
- `GET /auth`

Behavior:
- `200 OK` + header `Remote-User: <username>` when session is valid
- `401 Unauthorized` when not authenticated

Your proxy should redirect unauthenticated users to:
- `/login?rd=<original-url>`

## Kubernetes Hint

If you store config in a Secret:

```bash
kubectl create secret generic stupid-auth-users --from-file=users.yaml
```

Then mount it and set:
- `AUTH_CONFIG_FILE=/users.yaml`

## Environment Variables

| Variable | Scope | Default | Description |
| --- | --- | --- | --- |
| `AUTH_ADDRESS` | Runtime app | `0.0.0.0` | Bind address for the HTTP listener. |
| `AUTH_PORT` | Runtime app | `8000` | Bind port for the HTTP listener. |
| `AUTH_DOMAIN` | Runtime app | `localhost` | Allowed redirect domain + cookie domain. |
| `AUTH_COOKIE_EXPIRE` | Runtime app | `30` | Auth cookie expiration in days. |
| `AUTH_CONFIG_FILE` | Runtime app | `users.yaml` | Path to YAML auth config. |
| `TAILWIND_CSS` | Build/runtime wiring | build-provided | Embedded CSS file path used at compile time. |
| `STUPID_AUTH_VERSION` | Dev/deploy env | _(none)_ | Version metadata from Nix/Tilt wiring. |

## Security Scope

Designed for homelab usage, not enterprise/multi-tenant production.
