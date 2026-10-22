<?php

declare(strict_types=1);

namespace Muni\CasbinAuthz;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Muni\CasbinAuthz\Console\RefreshPolicyCommand;

class CasbinAuthzServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/casbin-authz.php', 'casbin-authz');

        $this->app->singleton(PolicyStore::class, function (Application $app): PolicyStore {
            $config = $app['config']['casbin-authz'];

            return new PolicyStore(
                connection: (string) $config['connection'],
                table: (string) $config['table'],
                snapshotPath: (string) $config['snapshot_path'],
                refreshSeconds: (int) $config['refresh_seconds'],
                dbTimeoutSeconds: (int) $config['db_timeout_seconds'],
            );
        });

        // Scoped: the enforcer memoizes the compiled policy per request.
        $this->app->scoped(AuthzEnforcer::class, function (Application $app): AuthzEnforcer {
            $config = $app['config']['casbin-authz'];

            return new AuthzEnforcer(
                store: $app->make(PolicyStore::class),
                modelPath: (string) $config['model_path'],
            );
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/casbin-authz.php' => config_path('casbin-authz.php'),
        ], 'casbin-authz-config');

        if ($this->app->runningInConsole()) {
            $this->commands([RefreshPolicyCommand::class]);
        }
    }
}
