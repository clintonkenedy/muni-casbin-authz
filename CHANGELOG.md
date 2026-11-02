# Changelog

## 0.2.0 — unreleased (no git tag)

- New `http` policy source (`CASBIN_SOURCE=http`): pulls the policy snapshot
  from the control plane `GET /policies/snapshot` over HTTPS using a Hydra
  `client_credentials` token (`client_secret_post`, scope `authz.read`).
  - New env vars: `CASBIN_SOURCE`, `CASBIN_SNAPSHOT_URL`, `CASBIN_TOKEN_URL`,
    `CASBIN_CLIENT_ID`, `CASBIN_CLIENT_SECRET`, `CASBIN_HTTP_TIMEOUT_SECONDS`.
  - Access token cached until 30 s before `expires_in`; single retry with a
    fresh token on `401`.
  - Conditional refresh via `If-None-Match`/`304`; the snapshot file now
    stores the `version` alongside `loaded_at` and `rules`.
  - Failure semantics identical to the database source: stale-forever on any
    failure, `PolicyUnavailableException` without a snapshot.
- `casbin-authz:refresh` now refreshes from the configured source.
- The `database` source behavior is unchanged.

## 0.1.0

- Initial release: embedded Casbin data plane reading `casbin_rule` from the
  database with a local JSON snapshot, stale-forever on DB failure, fail-closed
  without snapshot.
