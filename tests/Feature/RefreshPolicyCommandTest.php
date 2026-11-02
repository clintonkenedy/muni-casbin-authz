<?php

declare(strict_types=1);

namespace Muni\CasbinAuthz\Tests\Feature;

use Muni\CasbinAuthz\AuthzEnforcer;
use Muni\CasbinAuthz\Tests\TestCase;

class RefreshPolicyCommandTest extends TestCase
{
    public function test_refresh_command_reloads_immediately_and_outputs_count(): void
    {
        $this->seedDefaultPolicy();

        $enforcer = $this->app->make(AuthzEnforcer::class);

        // Fresh snapshot; new grant should not be visible yet.
        $this->assertFalse($enforcer->allows('87654321', 'sistrans', '/api/tuc/123', 'GET'));
        $this->insertRule('g', '87654321', 'operador', 'sistrans');
        $this->assertFalse($enforcer->allows('87654321', 'sistrans', '/api/tuc/123', 'GET'));

        // The command forces a reload regardless of snapshot age.
        $this->artisan('casbin-authz:refresh')
            ->expectsOutputToContain('3 rules')
            ->assertExitCode(0);

        $this->assertTrue($enforcer->allows('87654321', 'sistrans', '/api/tuc/123', 'GET'));
    }

    public function test_refresh_command_fails_with_non_zero_exit_when_db_is_down(): void
    {
        $this->dropPolicyTable();

        $this->artisan('casbin-authz:refresh')->assertExitCode(1);
    }

    public function test_refresh_command_prints_status(): void
    {
        $this->seedDefaultPolicy();

        // One substring only: Laravel's output mock lets a single written line
        // satisfy at most one expectsOutputToContain expectation.
        $this->artisan('casbin-authz:refresh')
            ->expectsOutputToContain('"source":"database","version":null')
            ->assertExitCode(0);

        $status = $this->app->make(\Muni\CasbinAuthz\PolicyStore::class)->status();
        $this->assertSame(0, $status['consecutive_failures']);
        $this->assertSame(0, $status['age_seconds']);
    }
}
