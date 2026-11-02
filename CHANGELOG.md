# Changelog

## 0.3.0 — 2026-11-02

- Failure backoff for both sources: after a failed refresh the next attempt is
  delayed, doubling from 5 s per consecutive failure up to
  `failure_backoff_max_seconds` (env `CASBIN_FAILURE_BACKOFF_MAX_SECONDS`,
  default 300). Inside the backoff window the stale snapshot is served with
  **no source call at all** (previously every request past `refresh_seconds`
  retried the source and could wait the full timeout while it was down). A
  successful refresh (200 or 304) resets the backoff. With no snapshot,
  `PolicyUnavailableException` is still thrown, but immediately (no network
  call) inside the backoff window. The backoff state lives in the cache store
  (same store as the refresh lock), not in the snapshot file, so it also works
  before any snapshot exists and failures never rewrite the snapshot.
- New `AuthzEnforcer::status()` / `PolicyStore::status()`:
  `{source, version, loaded_at, age_seconds, last_error_at,
  consecutive_failures, next_attempt_at}` (null when not applicable) for app
  health endpoints. `casbin-authz:refresh` prints it as JSON.
- Recommendation: use `CASBIN_SOURCE=http` for every system; the `database`
  source is kept only for backward compatibility.

## 0.2.0 — 2026-11-02

- New `http` policy source (`CASBIN_SOURCE=http`): pulls the policy snapshot
  from the control plane `GET /policies/snapshot` over HTTPS using a Hydra
  `client_credentials` token (`client_secret_post`, scope `authz.read`).
  - New env vars: `CASBIN_SOURCE`, `CASBIN_SNAPSHOT_URL`, `CASBIN_TOKEN_URL`,
    `CASBIN_CLIENT_ID`, `CASBIN_CLIENT_SECRET`, `CASBIN_HTTP_TIMEOUT_SECONDS`.
  - Access token cached until 30 s before `expires_in`; single retry with a
    fresh token on `401`.
  - Conditional refresh via `If-None-Match`/`304`; the snapshot file now
    stores the `version` alongside `loaded_at` and `rules`.
  - Requests a gzip-compressed snapshot (`Accept-Encoding: gzip`).
  - Failure semantics identical to the database source: stale-forever on any
    failure, `PolicyUnavailableException` without a snapshot.
- `casbin-authz:refresh` now refreshes from the configured source.
- The `database` source behavior is unchanged.

## 0.1.0

- Initial release: embedded Casbin data plane reading `casbin_rule` from the
  database with a local JSON snapshot, stale-forever on DB failure, fail-closed
  without snapshot.
