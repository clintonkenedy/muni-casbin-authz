# muni/casbin-authz

Embedded Casbin **authorization data plane** for Laravel backends.

Each backend enforces authorization locally from a policy snapshot read from the
shared `casbin_rule` table. The **control plane** (policy administration, the
`/check` HTTP service, writes to `casbin_rule`) remains the Go service
[`casbian-muni-puno`](https://github.com/MuniPuno/casbian-muni-puno); this
package only *reads* policies and evaluates them in-process, so authorization
keeps working even when the Casbin service or its database is down.

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
   is logged at most once per minute.
4. If the DB is unreachable **and no snapshot exists**, the package fails
   closed: `PolicyUnavailableException` is thrown — map it to
   `503 {"error":"authz_unavailable"}`.

## Installation

Add the repository to the consuming app's `composer.json`:

```json
{
    "repositories": [
        { "type": "path", "url": "../../muni-casbin-authz" }
    ],
    "_comment_repositories": [
        { "type": "vcs", "url": "git@github.com:MuniPuno/muni-casbin-authz.git" }
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
| `refresh_seconds`    | `CASBIN_REFRESH_SECONDS`| `30`                                  | Snapshot max age before a DB reload is attempted   |
| `db_timeout_seconds` | —                       | `2`                                   | Statement timeout for the policy read (pgsql)      |

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

- Policy snapshot refreshed from the DB at most every `refresh_seconds`.
- On DB failure the stale snapshot is kept **indefinitely** (fail-stale);
  a warning is logged at most once per 60 s.
- Without any snapshot, enforcement **fails closed** with
  `PolicyUnavailableException` → respond `503`.
- `casbin-authz:refresh` forces an immediate reload (non-zero exit on DB
  failure) — useful after policy changes or to pre-warm the snapshot:

```bash
php artisan casbin-authz:refresh
```

- `AuthzEnforcer::policyAge()` / `PolicyStore::policyAge()` return the snapshot
  age in seconds (or `null`) for health endpoints and alerting
  (alert when `casbin_policy_age_seconds > 600`).

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
        'casbin_policy_age_seconds' => $store->policyAge(),
    ]);
}
```
