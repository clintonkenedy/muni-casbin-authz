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

        $lock = Cache::lock(self::LOCK_KEY, self::LOCK_SECONDS);
        $acquired = $lock->get();

        if (! $acquired && $snapshot !== null) {
            // Another process is refreshing; keep serving the existing snapshot.
            return;
        }

        try {
            $this->refreshFromSource($snapshot);
        } catch (Throwable $e) {
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
        $this->refreshFromSource($this->snapshot());

        $fresh = $this->snapshot();

        return $fresh === null ? 0 : count($fresh['rules']);
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
