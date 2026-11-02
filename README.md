# muni/casbin-authz

Embedded Casbin **authorization data plane** for Laravel backends.

Each backend enforces authorization locally from a policy snapshot read from the
shared `casbin_rule` table. The **control plane** (policy administration, the
`/check` HTTP service, writes to `casbin_rule`) remains the Go service
[`casbian-muni-puno`](https://github.com/clintonkenedy/casbian-muni-puno); this
package only *reads* policies and evaluates them in-process, so authorization
keeps working even when the Casbin service or its database is down.

Two policy **sources** are supported (config `source`, env `CASBIN_SOURCE`):

- `http` (**recommended for every system**) — pull the policy snapshot from
  the control plane over HTTPS (`GET /policies/snapshot`). No system other
  than the Casbin service itself needs database credentials for the policy
  store.
- `database` (default, kept only for backward compatibility) — read the
  shared `casbin_rule` table directly.

Set `CASBIN_SOURCE=http` in new deployments.

## How it works

PHP-FPM has no long-lived process, so instead of an in-memory enforcer with a
watcher, the package keeps a local JSON snapshot
(`storage/app/casbin/policy.json`, `{loaded_at, rules}`):

1. On each check, if the snapshot is younger than `refresh_seconds` (default
   30), it is used as-is.
2. If the snapshot is stale (or missing), one DB reload is attempted (2 s
   statement timeout on PostgreSQL, guarded by a cache lock to avoid a
   stampede). On success the snapshot is rewritten atomically.
3. If the DB is unreachable, the **existing snapshot keeps being used
   indefinitely** (permission changes are frozen until recovery) and a warning
   is logged at most once per minute. The failure also starts a **retry
   backoff** (see below) so requests inside the window skip the source
   entirely instead of each paying the timeout.
4. If the DB is unreachable **and no snapshot exists**, the package fails
   closed: `PolicyUnavailableException` is thrown — map it to
   `503 {"error":"authz_unavailable"}`. Inside the backoff window the
   exception is thrown immediately, without a new source attempt.

The same flow applies to the `http` source, with the snapshot endpoint in
place of the DB read.

### Failure backoff

After a failed refresh the next attempt is delayed: 5 s after the first
failure, doubling per consecutive failure (5 → 10 → 20 → …) up to
`failure_backoff_max_seconds` (env `CASBIN_FAILURE_BACKOFF_MAX_SECONDS`,
default 300). During the window every request serves the stale snapshot with
**no network/DB call at all**. Any successful refresh (200 or 304) resets the
backoff. The backoff state is kept in the cache store (the same store used for
the refresh lock), not in the snapshot file, so it works even before any
snapshot exists and failures never rewrite the snapshot file.

## Installation

Add the repository to the consuming app's `composer.json`:

```json
{
    "repositories": [
        { "type": "path", "url": "../../muni-casbin-authz" }
    ],
    "_comment_repositories": [
        { "type": "vcs", "url": "https://github.com/clintonkenedy/muni-casbin-authz.git" }
    ]
}
```

```bash
composer require muni/casbin-authz
```

The service provider is auto-discovered. Optionally publish the config:

```bash
php artisan vendor:publish --tag=casbin-authz-config
```

Define the `casbin` database connection in `config/database.php`. The DB user
only needs **SELECT on `casbin_rule`** — the package never writes to the
database.

## Configuration

| Config key           | Env var                 | Default                               | Purpose                                            |
| -------------------- | ----------------------- | ------------------------------------- | -------------------------------------------------- |
| `connection`         | `CASBIN_DB_CONNECTION`  | `casbin`                              | Laravel DB connection used to read `casbin_rule`   |
| `table`              | —                       | `casbin_rule`                         | Policy table (xorm schema: `p_type, v0..v5`)       |
| `model_path`         | —                       | bundled `config/model.conf`           | Casbin model (identical to the control plane)      |
| `snapshot_path`      | —                       | `storage/app/casbin/policy.json`      | Local policy snapshot                              |
| `refresh_seconds`    | `CASBIN_REFRESH_SECONDS`| `30`                                  | Snapshot max age before a reload is attempted      |
| `db_timeout_seconds` | —                       | `2`                                   | Statement timeout for the policy read (pgsql)      |
| `failure_backoff_max_seconds` | `CASBIN_FAILURE_BACKOFF_MAX_SECONDS` | `300`        | Cap for the doubling retry backoff after failures  |
| `source`             | `CASBIN_SOURCE`         | `database`                            | Policy source: `database` or `http`                |
| `http.snapshot_url`  | `CASBIN_SNAPSHOT_URL`   | —                                     | Full URL of the control plane `/policies/snapshot` |
| `http.token_url`     | `CASBIN_TOKEN_URL`      | —                                     | Hydra `/oauth2/token` endpoint                     |
| `http.client_id`     | `CASBIN_CLIENT_ID`      | —                                     | Hydra client id (client_credentials)               |
| `http.client_secret` | `CASBIN_CLIENT_SECRET`  | —                                     | Hydra client secret (client_secret_post)           |
| `http.scope`         | —                       | `authz.read`                          | OAuth2 scope required by the snapshot endpoint     |
| `http.timeout_seconds` | `CASBIN_HTTP_TIMEOUT_SECONDS` | `2`                           | Timeout for token and snapshot requests            |

## HTTP snapshot source

When `CASBIN_SOURCE=http`, the package never touches the database. Instead it
refreshes the local snapshot from the control plane endpoint
`GET /policies/snapshot`, which returns
`{"version": "<sha256>", "rules": [[ptype, v0, ...], ...]}` with an
`ETag: "<version>"` header:

- Authentication: Hydra **client_credentials** (`client_secret_post`) with
  scope **`authz.read`**. **Each external system needs its own Hydra client**
  with that scope. The access token is cached until 30 s before `expires_in`;
  on a `401` from the snapshot URL a new token is fetched and the request is
  retried once.
- Conditional refresh: the stored snapshot `version` is sent as
  `If-None-Match`; a `304` keeps the rules and bumps `loaded_at` (it counts as
  a successful refresh).
- Resilience is identical to the database source: any failure (network,
  timeout, 5xx, malformed body, token error) keeps the last snapshot
  **indefinitely**, starts the retry backoff, and logs a throttled warning;
  with no snapshot at all, `PolicyUnavailableException` is thrown (map to
  `503`).
- The rules feed the exact same enforcer path as the database source, so
  authorization decisions are identical for the same policy.

```dotenv
CASBIN_SOURCE=http
CASBIN_SNAPSHOT_URL=https://casbin.example.gob.pe/policies/snapshot
CASBIN_TOKEN_URL=https://hydra.example.gob.pe/oauth2/token
CASBIN_CLIENT_ID=back-remote
CASBIN_CLIENT_SECRET=********
```

## Usage in a middleware

The model is `r = sub, dom, obj, act` with domain-scoped roles
(`g = user, role, domain`) and `keyMatch3` on objects, so `/api/tuc/{id}`
matches `/api/tuc/123`. In this deployment `sub` is the user's DNI and `dom`
is the sistema's Hydra `client_id`.

```php
use Muni\CasbinAuthz\AuthzEnforcer;
use Muni\CasbinAuthz\Exceptions\PolicyUnavailableException;
use Muni\HydraAuth\HydraPrincipal;

class CasbinEnforce
{
    public function __construct(private AuthzEnforcer $enforcer)
    {
    }

    public function handle($request, \Closure $next)
    {
        /** @var HydraPrincipal $principal */
        $principal = $request->attributes->get('hydra');

        try {
            $allowed = $this->enforcer->allows(
                $principal->sub,                          // user DNI
                config('services.oauth.expected_aud'),    // domain = client_id
                '/'.$request->path(),
                $request->method(),
            );
        } catch (PolicyUnavailableException) {
            return response()->json(['error' => 'authz_unavailable'], 503);
        }

        if (! $allowed) {
            return response()->json(['error' => 'forbidden'], 403);
        }

        return $next($request);
    }
}
```

`AuthzEnforcer` is registered as a **scoped** binding: the compiled enforcer is
memoized per request.

## Resilience semantics

- Policy snapshot refreshed from the configured source at most every
  `refresh_seconds`.
- On source failure (DB or HTTP) the stale snapshot is kept **indefinitely**
  (fail-stale); a warning is logged at most once per 60 s and a doubling retry
  backoff (5 s → `failure_backoff_max_seconds`) prevents every request from
  paying the source timeout while it is down.
- Without any snapshot, enforcement **fails closed** with
  `PolicyUnavailableException` → respond `503`.
- `casbin-authz:refresh` forces an immediate reload from the configured source
  (non-zero exit on failure) — useful after policy changes or to pre-warm the
  snapshot:

```bash
php artisan casbin-authz:refresh
```

- `AuthzEnforcer::policyAge()` / `PolicyStore::policyAge()` return the snapshot
  age in seconds (or `null`) for health endpoints and alerting
  (alert when `casbin_policy_age_seconds > 600`).
- `AuthzEnforcer::status()` / `PolicyStore::status()` return a health map for
  monitoring endpoints — fields are `null` when not applicable:

```json
{
    "source": "http",
    "version": "<sha256>",
    "loaded_at": 1767312000,
    "age_seconds": 12,
    "last_error_at": null,
    "consecutive_failures": 0,
    "next_attempt_at": null
}
```

  `casbin-authz:refresh` prints the same JSON after each run.

## Health endpoint (recommended)

The snapshot refreshes **lazily**, only when a request is authorized. On an idle
system (nights, weekends) its age keeps growing and a `policy age > N` alert would
fire even though everything is healthy. Call `refreshIfStale()` from your health
endpoint so monitoring polls keep the snapshot fresh and the metric honest:

```php
public function __invoke(PolicyStore $store): JsonResponse
{
    try {
        $store->refreshIfStale();
    } catch (PolicyUnavailableException) {
        // no snapshot and DB down → age is null
    }

    return response()->json([
        'status' => 'ok',
        'casbin' => $store->status(),
    ]);
}
```
