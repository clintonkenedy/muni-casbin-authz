<?php

declare(strict_types=1);

namespace Muni\CasbinAuthz\Tests\Feature;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Muni\CasbinAuthz\AuthzEnforcer;
use Muni\CasbinAuthz\Exceptions\PolicyUnavailableException;
use Muni\CasbinAuthz\Tests\TestCase;

class HttpSourceTest extends TestCase
{
    private const TOKEN_URL = 'https://hydra.test/oauth2/token';

    private const SNAPSHOT_URL = 'https://casbin.test/policies/snapshot';

    private const VERSION_1 = 'a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8';

    private const VERSION_2 = 'ffe2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6ffff';

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('casbin-authz.source', 'http');
        $app['config']->set('casbin-authz.http.snapshot_url', self::SNAPSHOT_URL);
        $app['config']->set('casbin-authz.http.token_url', self::TOKEN_URL);
        $app['config']->set('casbin-authz.http.client_id', 'back-remote');
        $app['config']->set('casbin-authz.http.client_secret', 'remote-secret');
    }

    /**
     * @return array<int, array<int, string>>
     */
    private function defaultRules(): array
    {
        return [
            ['p', 'operador', 'sistrans', '/api/tuc/{id}', 'GET'],
            ['g', '12345678', 'operador', 'sistrans'],
        ];
    }

    /**
     * @param array<int, array<int, string>> $rules
     */
    private function snapshotResponse(string $version, array $rules): \GuzzleHttp\Promise\PromiseInterface
    {
        return Http::response(
            ['version' => $version, 'rules' => $rules],
            200,
            ['ETag' => '"'.$version.'"', 'Cache-Control' => 'no-store'],
        );
    }

    private function tokenResponse(string $token, int $expiresIn = 3600): \GuzzleHttp\Promise\PromiseInterface
    {
        return Http::response([
            'access_token' => $token,
            'expires_in' => $expiresIn,
            'token_type' => 'bearer',
        ]);
    }

    public function test_http_source_loads_rules_and_enforces(): void
    {
        Http::fake([
            self::TOKEN_URL => $this->tokenResponse('tok-1'),
            self::SNAPSHOT_URL => $this->snapshotResponse(self::VERSION_1, $this->defaultRules()),
        ]);

        $enforcer = $this->app->make(AuthzEnforcer::class);

        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));
        $this->assertFalse($enforcer->allows('99999999', 'sistrans', '/api/tuc/123', 'GET'));

        Http::assertSent(function (Request $request): bool {
            return $request->url() === self::TOKEN_URL
                && $request['grant_type'] === 'client_credentials'
                && $request['client_id'] === 'back-remote'
                && $request['client_secret'] === 'remote-secret'
                && $request['scope'] === 'authz.read';
        });

        Http::assertSent(function (Request $request): bool {
            return $request->url() === self::SNAPSHOT_URL
                && $request->hasHeader('Authorization', 'Bearer tok-1');
        });
    }

    public function test_sends_if_none_match_with_stored_version_on_refresh(): void
    {
        Http::fake([
            self::TOKEN_URL => $this->tokenResponse('tok-1'),
            self::SNAPSHOT_URL => Http::sequence()
                ->push(['version' => self::VERSION_1, 'rules' => $this->defaultRules()])
                ->push(['version' => self::VERSION_1, 'rules' => $this->defaultRules()]),
        ]);

        $enforcer = $this->app->make(AuthzEnforcer::class);
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));

        $this->travel(31)->seconds();
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));

        Http::assertSent(function (Request $request): bool {
            return $request->url() === self::SNAPSHOT_URL
                && $request->hasHeader('If-None-Match', '"'.self::VERSION_1.'"');
        });
    }

    public function test_304_keeps_rules_and_bumps_loaded_at(): void
    {
        Http::fake([
            self::TOKEN_URL => $this->tokenResponse('tok-1'),
            self::SNAPSHOT_URL => Http::sequence()
                ->push(['version' => self::VERSION_1, 'rules' => $this->defaultRules()])
                ->push('', 304),
        ]);

        $enforcer = $this->app->make(AuthzEnforcer::class);
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));

        $this->travel(31)->seconds();
        $this->assertSame(31, $enforcer->policyAge());

        // The 304 counts as a successful refresh: rules kept, loaded_at bumped.
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));
        $this->assertSame(0, $enforcer->policyAge());
    }

    public function test_401_triggers_token_refresh_and_single_retry(): void
    {
        Http::fake([
            self::TOKEN_URL => Http::sequence()
                ->push(['access_token' => 'tok-stale', 'expires_in' => 3600, 'token_type' => 'bearer'])
                ->push(['access_token' => 'tok-fresh', 'expires_in' => 3600, 'token_type' => 'bearer']),
            self::SNAPSHOT_URL => Http::sequence()
                ->push(['error' => 'invalid_token'], 401)
                ->push(['version' => self::VERSION_1, 'rules' => $this->defaultRules()]),
        ]);

        $enforcer = $this->app->make(AuthzEnforcer::class);

        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));

        Http::assertSentCount(4); // token, 401 snapshot, new token, retried snapshot

        Http::assertSent(function (Request $request): bool {
            return $request->url() === self::SNAPSHOT_URL
                && $request->hasHeader('Authorization', 'Bearer tok-fresh');
        });
    }

    public function test_network_failure_keeps_stale_snapshot(): void
    {
        $calls = 0;

        Http::fake(function (Request $request) use (&$calls) {
            if ($request->url() === self::TOKEN_URL) {
                return $this->tokenResponse('tok-1');
            }

            $calls++;

            if ($calls === 1) {
                return $this->snapshotResponse(self::VERSION_1, $this->defaultRules());
            }

            throw new ConnectionException('connection refused');
        });

        $enforcer = $this->app->make(AuthzEnforcer::class);
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));

        $this->travel(31)->seconds();

        Log::shouldReceive('warning')->once();

        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));
        $this->assertFalse($enforcer->allows('99999999', 'sistrans', '/api/tuc/123', 'GET'));
    }

    public function test_malformed_body_keeps_stale_snapshot(): void
    {
        Http::fake([
            self::TOKEN_URL => $this->tokenResponse('tok-1'),
            self::SNAPSHOT_URL => Http::sequence()
                ->push(['version' => self::VERSION_1, 'rules' => $this->defaultRules()])
                ->push(['version' => self::VERSION_2, 'rules' => 'definitely-not-an-array']),
        ]);

        $enforcer = $this->app->make(AuthzEnforcer::class);
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));

        $this->travel(31)->seconds();

        Log::shouldReceive('warning')->once();

        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));
    }

    public function test_no_snapshot_and_failure_throws_policy_unavailable(): void
    {
        Http::fake([
            self::TOKEN_URL => $this->tokenResponse('tok-1'),
            self::SNAPSHOT_URL => Http::response(['error' => 'policy_unavailable'], 503),
        ]);

        $enforcer = $this->app->make(AuthzEnforcer::class);

        $this->expectException(PolicyUnavailableException::class);

        $enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET');
    }

    public function test_token_is_cached_across_refreshes(): void
    {
        Http::fake([
            self::TOKEN_URL => $this->tokenResponse('tok-1'),
            self::SNAPSHOT_URL => Http::sequence()
                ->push(['version' => self::VERSION_1, 'rules' => $this->defaultRules()])
                ->push(['version' => self::VERSION_1, 'rules' => $this->defaultRules()]),
        ]);

        $enforcer = $this->app->make(AuthzEnforcer::class);
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));

        $this->travel(31)->seconds();
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));

        // Two snapshot fetches, but only one token request (cached).
        $tokenRequests = 0;

        Http::assertSent(function (Request $request) use (&$tokenRequests): bool {
            if ($request->url() === self::TOKEN_URL) {
                $tokenRequests++;
            }

            return true;
        });

        $this->assertSame(1, $tokenRequests);
    }
}
