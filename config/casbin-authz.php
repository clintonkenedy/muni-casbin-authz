<?php

return [
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
];
