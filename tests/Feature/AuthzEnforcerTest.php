<?php

declare(strict_types=1);

namespace Muni\CasbinAuthz\Tests\Feature;

use Muni\CasbinAuthz\AuthzEnforcer;
use Muni\CasbinAuthz\Tests\TestCase;

class AuthzEnforcerTest extends TestCase
{
    public function test_key_match3_pattern_allows_concrete_path(): void
    {
        $this->seedDefaultPolicy();

        $enforcer = $this->app->make(AuthzEnforcer::class);

        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));
        $this->assertFalse($enforcer->allows('12345678', 'sistrans', '/api/other/123', 'GET'));
        $this->assertFalse($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'POST'));
    }

    public function test_domain_scoped_role_allows_only_in_its_domain(): void
    {
        $this->seedDefaultPolicy();
        // Same object/action policy exists in another domain, but the role
        // grant for the user only exists in 'sistrans'.
        $this->insertRule('p', 'operador', 'otherdom', '/api/tuc/{id}', 'GET');

        $enforcer = $this->app->make(AuthzEnforcer::class);

        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));
        $this->assertFalse($enforcer->allows('12345678', 'otherdom', '/api/tuc/123', 'GET'));
    }

    public function test_unknown_user_is_denied(): void
    {
        $this->seedDefaultPolicy();

        $enforcer = $this->app->make(AuthzEnforcer::class);

        $this->assertFalse($enforcer->allows('99999999', 'sistrans', '/api/tuc/123', 'GET'));
    }

    public function test_policy_age_reports_snapshot_age(): void
    {
        $this->seedDefaultPolicy();

        $enforcer = $this->app->make(AuthzEnforcer::class);

        $this->assertNull($enforcer->policyAge());

        $enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET');

        $this->assertSame(0, $enforcer->policyAge());

        $this->travel(10)->seconds();

        $this->assertSame(10, $enforcer->policyAge());
    }
}
