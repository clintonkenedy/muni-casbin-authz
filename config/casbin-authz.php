<?php

return [
    // Policy source: 'database' (read casbin_rule directly) or 'http'
    // (pull GET /policies/snapshot from the Casbin control plane over HTTPS).
    'source' => env('CASBIN_SOURCE', 'database'),

    // Laravel database connection used to read the casbin_rule table (read-only).
    'connection' => env('CASBIN_DB_CONNECTION', 'casbin'),

    // Table written by the Casbin control plane (xorm schema: p_type, v0..v5).
    'table' => 'casbin_rule',

    // Casbin model file. Defaults to the model bundled with the package,
    // semantically identical to the Go control plane model.
    'model_path' => __DIR__.'/model.conf',

    // Local policy snapshot ({loaded_at, rules}) written atomically.
    'snapshot_path' => storage_path('app/casbin/policy.json'),

    // Snapshot older than this many seconds triggers a DB reload attempt.
    'refresh_seconds' => (int) env('CASBIN_REFRESH_SECONDS', 30),

    // Statement timeout applied to the policy read (pgsql).
    'db_timeout_seconds' => 2,

    // Settings for the 'http' source (ignored for 'database').
    'http' => [
        // Full URL of the control plane snapshot endpoint, e.g.
        // https://casbin.example.gob.pe/policies/snapshot
        'snapshot_url' => env('CASBIN_SNAPSHOT_URL'),

        // Hydra token endpoint, e.g. https://hydra.example.gob.pe/oauth2/token
        'token_url' => env('CASBIN_TOKEN_URL'),

        // Hydra client (client_credentials, client_secret_post) with scope authz.read.
        'client_id' => env('CASBIN_CLIENT_ID'),
        'client_secret' => env('CASBIN_CLIENT_SECRET'),

        // OAuth2 scope required by the snapshot endpoint.
        'scope' => 'authz.read',

        // Timeout (seconds) for both the token and snapshot requests.
        'timeout_seconds' => (int) env('CASBIN_HTTP_TIMEOUT_SECONDS', 2),
    ],
];
