<?php

declare(strict_types=1);

namespace Muni\CasbinAuthz\Console;

use Illuminate\Console\Command;
use Muni\CasbinAuthz\PolicyStore;
use Throwable;

class RefreshPolicyCommand extends Command
{
    protected $signature = 'casbin-authz:refresh';

    protected $description = 'Force a reload of the Casbin policy snapshot from the database.';

    public function handle(PolicyStore $store): int
    {
        try {
            $rules = $store->load();
            $store->writeSnapshot($rules);
        } catch (Throwable $e) {
            $this->error('Casbin policy refresh failed: '.$e->getMessage());

            return self::FAILURE;
        }

        $this->info(sprintf('Casbin policy snapshot refreshed: %d rules.', count($rules)));

        return self::SUCCESS;
    }
}
