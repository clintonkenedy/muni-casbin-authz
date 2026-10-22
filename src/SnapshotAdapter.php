<?php

declare(strict_types=1);

namespace Muni\CasbinAuthz;

use Casbin\Model\Model;
use Casbin\Persist\Adapter;

/**
 * Read-only in-memory adapter feeding php-casbin from snapshot rules.
 */
class SnapshotAdapter implements Adapter
{
    /**
     * @param array<int, array<int, string>> $rules rules as [p_type, v0, v1, ...]
     */
    public function __construct(private readonly array $rules)
    {
    }

    public function loadPolicy(Model $model): void
    {
        foreach ($this->rules as $rule) {
            $rule = array_values(array_map(strval(...), $rule));
            $ptype = array_shift($rule);

            if ($ptype === null || $ptype === '' || $rule === []) {
                continue;
            }

            $section = substr($ptype, 0, 1);

            if ($section !== 'p' && $section !== 'g') {
                continue;
            }

            $model->addPolicy($section, $ptype, $rule);
        }
    }

    public function savePolicy(Model $model): void
    {
        // Read-only adapter: persistence is owned by the control plane.
    }

    public function addPolicy(string $sec, string $ptype, array $rule): void
    {
        // Read-only adapter.
    }

    public function removePolicy(string $sec, string $ptype, array $rule): void
    {
        // Read-only adapter.
    }

    public function removeFilteredPolicy(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues): void
    {
        // Read-only adapter.
    }
}
