<?php

declare(strict_types=1);

namespace Muni\CasbinAuthz\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Muni\CasbinAuthz\CasbinAuthzServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected string $snapshotPath;

    protected function setUp(): void
    {
        parent::setUp();

        Schema::connection('casbin')->create('casbin_rule', function (Blueprint $table): void {
            $table->increments('id');
            $table->string('p_type')->nullable();
            $table->string('v0')->nullable();
            $table->string('v1')->nullable();
            $table->string('v2')->nullable();
            $table->string('v3')->nullable();
            $table->string('v4')->nullable();
            $table->string('v5')->nullable();
        });
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();

        if (isset($this->snapshotPath) && is_file($this->snapshotPath)) {
            @unlink($this->snapshotPath);
        }

        parent::tearDown();
    }

    protected function getPackageProviders($app): array
    {
        return [CasbinAuthzServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $this->snapshotPath = sys_get_temp_dir().'/casbin-authz-tests/'.uniqid('', true).'/policy.json';

        $app['config']->set('cache.default', 'array');
        $app['config']->set('database.connections.casbin', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $app['config']->set('casbin-authz.connection', 'casbin');
        $app['config']->set('casbin-authz.snapshot_path', $this->snapshotPath);
        $app['config']->set('casbin-authz.refresh_seconds', 30);
    }

    /**
     * Insert a casbin_rule row ([p_type, v0, v1, ...]).
     */
    protected function insertRule(string ...$values): void
    {
        $columns = ['p_type', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5'];

        DB::connection('casbin')->table('casbin_rule')->insert(
            array_combine(array_slice($columns, 0, count($values)), $values),
        );
    }

    protected function seedDefaultPolicy(): void
    {
        $this->insertRule('p', 'operador', 'sistrans', '/api/tuc/{id}', 'GET');
        $this->insertRule('g', '12345678', 'operador', 'sistrans');
    }

    protected function dropPolicyTable(): void
    {
        Schema::connection('casbin')->drop('casbin_rule');
    }
}
