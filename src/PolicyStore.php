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
 * Reads casbin_rule from the database and maintains a local JSON snapshot
 * ({loaded_at, rules}) that survives database outages indefinitely.
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
     * @return array{loaded_at: int, rules: array<int, array<int, string>>}|null
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

        return [
            'loaded_at' => (int) $decoded['loaded_at'],
            'rules' => $decoded['rules'],
        ];
    }

    /**
     * Atomically persist a new snapshot (temp file + rename).
     *
     * @param array<int, array<int, string>> $rules
     */
    public function writeSnapshot(array $rules): void
    {
        $directory = dirname($this->snapshotPath);

        if (! is_dir($directory) && ! mkdir($directory, 0775, true) && ! is_dir($directory)) {
            throw new RuntimeException(sprintf('Unable to create snapshot directory "%s".', $directory));
        }

        $payload = json_encode([
            'loaded_at' => Carbon::now()->getTimestamp(),
            'rules' => array_values($rules),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

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
     * Refresh the snapshot from the database when it is missing or older than
     * refresh_seconds. On database failure the existing snapshot is kept
     * indefinitely; without any snapshot, PolicyUnavailableException is thrown.
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
            $this->writeSnapshot($this->load());
        } catch (Throwable $e) {
            $this->warnThrottled($e);

            if ($snapshot === null) {
                throw new PolicyUnavailableException(
                    'Casbin policy unavailable: no local snapshot and the database load failed.',
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
            Log::warning('casbin-authz: policy refresh from database failed; keeping existing snapshot.', [
                'connection' => $this->connection,
                'error' => $e->getMessage(),
            ]);
        }
    }
}
