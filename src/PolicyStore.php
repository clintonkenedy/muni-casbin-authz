<?php

declare(strict_types=1);

namespace Muni\CasbinAuthz;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Muni\CasbinAuthz\Exceptions\PolicyUnavailableException;
use RuntimeException;
use Throwable;

/**
 * Maintains a local JSON snapshot ({loaded_at, version?, rules}) of the
 * Casbin policy, refreshed from the configured source (database or http),
 * surviving source outages indefinitely.
 */
class PolicyStore
{
    private const LOCK_KEY = 'casbin-authz:refresh';

    private const WARNING_THROTTLE_KEY = 'casbin-authz:refresh-warning';

    private const BACKOFF_KEY = 'casbin-authz:backoff';

    private const BACKOFF_BASE_SECONDS = 5;

    private const LOCK_SECONDS = 5;

    private const WARNING_THROTTLE_SECONDS = 60;

    public function __construct(
        private readonly string $connection,
        private readonly string $table,
        private readonly string $snapshotPath,
        private readonly int $refreshSeconds,
        private readonly int $dbTimeoutSeconds,
        private readonly string $source = 'database',
        private readonly ?HttpPolicySource $httpSource = null,
        private readonly int $failureBackoffMaxSeconds = 300,
    ) {
    }

    /**
     * Load every policy rule from the database.
     *
     * @return array<int, array<int, string>> rules as [p_type, v0, v1, ...]
     */
    public function load(): array
    {
        $connection = DB::connection($this->connection);

        if ($connection->getDriverName() === 'pgsql') {
            $connection->statement(sprintf('SET statement_timeout = %d', $this->dbTimeoutSeconds * 1000));
        }

        $rows = $connection->table($this->table)
            ->get(['p_type', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5']);

        $rules = [];

        foreach ($rows as $row) {
            $rule = [(string) $row->p_type];

            foreach (['v0', 'v1', 'v2', 'v3', 'v4', 'v5'] as $column) {
                $rule[] = $row->{$column};
            }

            // Drop trailing unused columns (null or empty string).
            while (count($rule) > 1 && ($rule[count($rule) - 1] === null || $rule[count($rule) - 1] === '')) {
                array_pop($rule);
            }

            $rules[] = array_map(strval(...), $rule);
        }

        return $rules;
    }

    /**
     * Read the current snapshot, or null when missing/unreadable.
     *
     * @return array{loaded_at: int, version: string|null, rules: array<int, array<int, string>>}|null
     */
    public function snapshot(): ?array
    {
        if (! is_file($this->snapshotPath)) {
            return null;
        }

        $raw = @file_get_contents($this->snapshotPath);

        if ($raw === false) {
            return null;
        }

        $decoded = json_decode($raw, true);

        if (! is_array($decoded) || ! isset($decoded['loaded_at'], $decoded['rules']) || ! is_array($decoded['rules'])) {
            return null;
        }

        $version = $decoded['version'] ?? null;

        return [
            'loaded_at' => (int) $decoded['loaded_at'],
            'version' => is_string($version) && $version !== '' ? $version : null,
            'rules' => $decoded['rules'],
        ];
    }

    /**
     * Atomically persist a new snapshot (temp file + rename).
     *
     * @param array<int, array<int, string>> $rules
     */
    public function writeSnapshot(array $rules, ?string $version = null): void
    {
        $directory = dirname($this->snapshotPath);

        if (! is_dir($directory) && ! mkdir($directory, 0775, true) && ! is_dir($directory)) {
            throw new RuntimeException(sprintf('Unable to create snapshot directory "%s".', $directory));
        }

        $data = ['loaded_at' => Carbon::now()->getTimestamp()];

        if ($version !== null) {
            $data['version'] = $version;
        }

        $data['rules'] = array_values($rules);

        $payload = json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        $temp = $this->snapshotPath.'.'.uniqid('tmp', true);

        if (file_put_contents($temp, $payload) === false) {
            throw new RuntimeException(sprintf('Unable to write snapshot temp file "%s".', $temp));
        }

        if (! rename($temp, $this->snapshotPath)) {
            @unlink($temp);

            throw new RuntimeException(sprintf('Unable to move snapshot into place at "%s".', $this->snapshotPath));
        }
    }

    /**
     * Refresh the snapshot from the configured source when it is missing or
     * older than refresh_seconds. On source failure the existing snapshot is
     * kept indefinitely; without any snapshot, PolicyUnavailableException is
     * thrown.
     */
    public function refreshIfStale(): void
    {
        $snapshot = $this->snapshot();

        if ($snapshot !== null) {
            $age = Carbon::now()->getTimestamp() - $snapshot['loaded_at'];

            if ($age < $this->refreshSeconds) {
                return;
            }
        }

        $backoff = $this->backoffState();

        if ($backoff !== null && Carbon::now()->getTimestamp() < $backoff['next_attempt_at']) {
            if ($snapshot === null) {
                throw new PolicyUnavailableException(sprintf(
                    'Casbin policy unavailable: no local snapshot and the %s source is in its failure backoff window.',
                    $this->source,
                ));
            }

            // Inside the backoff window: serve the stale snapshot, no source call.
            return;
        }

        $lock = Cache::lock(self::LOCK_KEY, self::LOCK_SECONDS);
        $acquired = $lock->get();

        if (! $acquired && $snapshot !== null) {
            // Another process is refreshing; keep serving the existing snapshot.
            return;
        }

        try {
            $this->refreshFromSource($snapshot);
            $this->resetBackoff();
        } catch (Throwable $e) {
            $this->recordFailure();
            $this->warnThrottled($e);

            if ($snapshot === null) {
                throw new PolicyUnavailableException(
                    sprintf('Casbin policy unavailable: no local snapshot and the %s load failed.', $this->source),
                    0,
                    $e,
                );
            }
        } finally {
            if ($acquired) {
                $lock->release();
            }
        }
    }

    /**
     * Force a refresh from the configured source regardless of snapshot age.
     * Throws on failure; returns the number of rules in the fresh snapshot.
     */
    public function refreshNow(): int
    {
        try {
            $this->refreshFromSource($this->snapshot());
        } catch (Throwable $e) {
            $this->recordFailure();

            throw $e;
        }

        $this->resetBackoff();

        $fresh = $this->snapshot();

        return $fresh === null ? 0 : count($fresh['rules']);
    }

    /**
     * Health snapshot for monitoring endpoints. Fields are null when not
     * applicable (e.g. no snapshot yet, no recorded failure).
     *
     * @return array{source: string, version: string|null, loaded_at: int|null, age_seconds: int|null, last_error_at: int|null, consecutive_failures: int, next_attempt_at: int|null}
     */
    public function status(): array
    {
        $snapshot = $this->snapshot();
        $backoff = $this->backoffState();

        return [
            'source' => $this->source,
            'version' => $snapshot['version'] ?? null,
            'loaded_at' => $snapshot['loaded_at'] ?? null,
            'age_seconds' => $snapshot === null ? null : max(0, Carbon::now()->getTimestamp() - $snapshot['loaded_at']),
            'last_error_at' => $backoff['last_error_at'] ?? null,
            'consecutive_failures' => $backoff['consecutive_failures'] ?? 0,
            'next_attempt_at' => $backoff['next_attempt_at'] ?? null,
        ];
    }

    /**
     * Refresh the snapshot once from the configured source.
     *
     * @param array{loaded_at: int, version: string|null, rules: array<int, array<int, string>>}|null $snapshot
     */
    private function refreshFromSource(?array $snapshot): void
    {
        if ($this->source === 'http') {
            if ($this->httpSource === null) {
                throw new RuntimeException('casbin-authz: source is "http" but no HTTP source is configured.');
            }

            $result = $this->httpSource->fetch($snapshot['version'] ?? null);

            if ($result['not_modified']) {
                // 304: rules are unchanged; bump loaded_at so the refresh counts.
                $this->writeSnapshot($snapshot['rules'] ?? [], $result['version']);

                return;
            }

            $this->writeSnapshot($result['rules'] ?? [], $result['version']);

            return;
        }

        $this->writeSnapshot($this->load());
    }

    /**
     * Age of the current snapshot in seconds, or null when no snapshot exists.
     */
    public function policyAge(): ?int
    {
        $snapshot = $this->snapshot();

        if ($snapshot === null) {
            return null;
        }

        return max(0, Carbon::now()->getTimestamp() - $snapshot['loaded_at']);
    }

    /**
     * Current failure backoff state, or null when the last refresh succeeded.
     *
     * @return array{consecutive_failures: int, last_error_at: int, next_attempt_at: int}|null
     */
    private function backoffState(): ?array
    {
        $state = Cache::get(self::BACKOFF_KEY);

        if (! is_array($state) || ! isset($state['consecutive_failures'], $state['last_error_at'], $state['next_attempt_at'])) {
            return null;
        }

        return [
            'consecutive_failures' => (int) $state['consecutive_failures'],
            'last_error_at' => (int) $state['last_error_at'],
            'next_attempt_at' => (int) $state['next_attempt_at'],
        ];
    }

    /**
     * Record a failed refresh: the retry delay doubles from 5 s per
     * consecutive failure, capped at failure_backoff_max_seconds.
     */
    private function recordFailure(): void
    {
        $failures = ($this->backoffState()['consecutive_failures'] ?? 0) + 1;

        $delay = self::BACKOFF_BASE_SECONDS;

        for ($i = 1; $i < $failures && $delay < $this->failureBackoffMaxSeconds; $i++) {
            $delay *= 2;
        }

        $delay = min($delay, max(self::BACKOFF_BASE_SECONDS, $this->failureBackoffMaxSeconds));

        $now = Carbon::now()->getTimestamp();

        Cache::put(self::BACKOFF_KEY, [
            'consecutive_failures' => $failures,
            'last_error_at' => $now,
            'next_attempt_at' => $now + $delay,
        ], max($this->failureBackoffMaxSeconds * 2, 600));
    }

    private function resetBackoff(): void
    {
        Cache::forget(self::BACKOFF_KEY);
    }

    private function warnThrottled(Throwable $e): void
    {
        if (Cache::add(self::WARNING_THROTTLE_KEY, 1, self::WARNING_THROTTLE_SECONDS)) {
            Log::warning(sprintf('casbin-authz: policy refresh from %s failed; keeping existing snapshot.', $this->source), [
                'source' => $this->source,
                'connection' => $this->connection,
                'error' => $e->getMessage(),
            ]);
        }
    }
}
