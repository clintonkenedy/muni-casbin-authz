<?php

declare(strict_types=1);

namespace Muni\CasbinAuthz\Tests\Feature;

use Illuminate\Support\Facades\Log;
use Muni\CasbinAuthz\AuthzEnforcer;
use Muni\CasbinAuthz\Exceptions\PolicyUnavailableException;
use Muni\CasbinAuthz\Tests\TestCase;

class ResilienceTest extends TestCase
{
    public function test_db_down_with_snapshot_keeps_allowing_and_logs_warning(): void
    {
        $this->seedDefaultPolicy();

        $enforcer = $this->app->make(AuthzEnforcer::class);

        // Build the initial snapshot while the DB is healthy.
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));

        // Age the snapshot past refresh_seconds, then break the DB.
        $this->travel(31)->seconds();
        $this->dropPolicyTable();

        Log::shouldReceive('warning')->once();

        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));
        $this->assertFalse($enforcer->allows('99999999', 'sistrans', '/api/tuc/123', 'GET'));
    }

    public function test_warning_is_throttled_to_once_per_minute(): void
    {
        $this->seedDefaultPolicy();

        $enforcer = $this->app->make(AuthzEnforcer::class);
        $enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET');

        $this->travel(31)->seconds();
        $this->dropPolicyTable();

        Log::shouldReceive('warning')->once();

        // Both calls hit a stale snapshot + failing DB, but only one warning.
        $enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET');
        $enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET');
    }

    public function test_db_down_without_snapshot_throws_policy_unavailable(): void
    {
        $this->dropPolicyTable();

        $enforcer = $this->app->make(AuthzEnforcer::class);

        $this->expectException(PolicyUnavailableException::class);

        $enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET');
    }

    public function test_refresh_interval_is_respected(): void
    {
        $this->seedDefaultPolicy();

        $enforcer = $this->app->make(AuthzEnforcer::class);

        $this->assertFalse($enforcer->allows('87654321', 'sistrans', '/api/tuc/123', 'GET'));

        // New grant in the DB is not visible until the snapshot goes stale.
        $this->insertRule('g', '87654321', 'operador', 'sistrans');

        $this->travel(10)->seconds();
        $this->assertFalse($enforcer->allows('87654321', 'sistrans', '/api/tuc/123', 'GET'));

        $this->travel(21)->seconds();
        $this->assertTrue($enforcer->allows('87654321', 'sistrans', '/api/tuc/123', 'GET'));
    }
}
