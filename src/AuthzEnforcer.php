<?php

declare(strict_types=1);

namespace Muni\CasbinAuthz;

use Casbin\Enforcer;
use Casbin\Model\Model;
use Muni\CasbinAuthz\Exceptions\PolicyUnavailableException;
use Throwable;

/**
 * Request-scoped Casbin enforcer built from the local policy snapshot.
 */
class AuthzEnforcer
{
    private ?Enforcer $enforcer = null;

    private ?string $builtFingerprint = null;

    public function __construct(
        private readonly PolicyStore $store,
        private readonly string $modelPath,
    ) {
    }

    /**
     * Check whether the subject may perform the action on the object within
     * the domain. Fails closed (false) on any Casbin error; propagates
     * PolicyUnavailableException when no policy data exists at all.
     */
    public function allows(string $sub, string $dom, string $obj, string $act): bool
    {
        $this->store->refreshIfStale();

        try {
            return (bool) $this->enforcer()->enforce($sub, $dom, $obj, $act);
        } catch (PolicyUnavailableException $e) {
            throw $e;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Age of the current snapshot in seconds, or null when no snapshot exists.
     */
    public function policyAge(): ?int
    {
        return $this->store->policyAge();
    }

    private function enforcer(): Enforcer
    {
        $snapshot = $this->store->snapshot();

        if ($snapshot === null) {
            throw new PolicyUnavailableException('Casbin policy unavailable: no local snapshot exists.');
        }

        $fingerprint = $snapshot['loaded_at'].':'.md5(json_encode($snapshot['rules']) ?: '');

        if ($this->enforcer !== null && $this->builtFingerprint === $fingerprint) {
            return $this->enforcer;
        }

        $model = new Model();
        $model->loadModel($this->modelPath);

        $this->enforcer = new Enforcer($model, new SnapshotAdapter($snapshot['rules']));
        $this->builtFingerprint = $fingerprint;

        return $this->enforcer;
    }
}
