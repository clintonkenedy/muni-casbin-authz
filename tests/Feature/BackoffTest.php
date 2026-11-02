<?php

declare(strict_types=1);

namespace Muni\CasbinAuthz\Tests\Feature;

use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Muni\CasbinAuthz\AuthzEnforcer;
use Muni\CasbinAuthz\Exceptions\PolicyUnavailableException;
use Muni\CasbinAuthz\Tests\TestCase;

class BackoffTest extends TestCase
{
    private const TOKEN_URL = 'https://hydra.test/oauth2/token';

    private const SNAPSHOT_URL = 'https://casbin.test/policies/snapshot';

    private const VERSION_1 = 'a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8';

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

    private function tokenResponse(): PromiseInterface
    {
        return Http::response([
            'access_token' => 'tok-1',
            'expires_in' => 3600,
            'token_type' => 'bearer',
        ]);
    }

    /**
     * Fake: first snapshot request succeeds, every later one fails with 503.
     * $snapshotCalls counts only snapshot requests (not token requests).
     */
    private function fakeSuccessThenFailures(int &$snapshotCalls, int $successes = 1): void
    {
        Http::fake(function (Request $request) use (&$snapshotCalls, $successes) {
            if ($request->url() === self::TOKEN_URL) {
                return $this->tokenResponse();
            }

            $snapshotCalls++;

            if ($snapshotCalls <= $successes) {
                return Http::response(
                    ['version' => self::VERSION_1, 'rules' => $this->defaultRules()],
                    200,
                    ['ETag' => '"'.self::VERSION_1.'"'],
                );
            }

            return Http::response(['error' => 'down'], 503);
        });
    }

    public function test_backoff_window_serves_stale_without_http_request(): void
    {
        $snapshotCalls = 0;
        $this->fakeSuccessThenFailures($snapshotCalls);
        Log::shouldReceive('warning');

        $enforcer = $this->app->make(AuthzEnforcer::class);
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));
        $this->assertSame(1, $snapshotCalls);

        // Stale snapshot + failing source: one attempt, failure recorded.
        $this->travel(31)->seconds();
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));
        $this->assertSame(2, $snapshotCalls);

        // Inside the 5 s backoff window: stale decision, zero network calls.
        $this->travel(2)->seconds();
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));
        $this->assertFalse($enforcer->allows('99999999', 'sistrans', '/api/tuc/123', 'GET'));
        $this->assertSame(2, $snapshotCalls);

        // Past the window: one new attempt.
        $this->travel(4)->seconds();
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));
        $this->assertSame(3, $snapshotCalls);
    }

    public function test_backoff_doubles_and_is_capped(): void
    {
        $this->app['config']->set('casbin-authz.failure_backoff_max_seconds', 20);

        $snapshotCalls = 0;
        $this->fakeSuccessThenFailures($snapshotCalls);
        Log::shouldReceive('warning');

        $enforcer = $this->app->make(AuthzEnforcer::class);
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));

        $expectedDelays = [5, 10, 20, 20];

        $this->travel(31)->seconds();

        foreach ($expectedDelays as $i => $delay) {
            $enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET');

            $status = $enforcer->status();
            $this->assertSame($i + 1, $status['consecutive_failures']);
            $this->assertSame($delay, $status['next_attempt_at'] - $status['last_error_at'], "failure #".($i + 1));

            // Move just past the current window so the next call retries.
            $this->travel($delay + 1)->seconds();
        }

        $this->assertSame(1 + count($expectedDelays), $snapshotCalls);
    }

    public function test_successful_refresh_resets_backoff(): void
    {
        $snapshotCalls = 0;

        Http::fake(function (Request $request) use (&$snapshotCalls) {
            if ($request->url() === self::TOKEN_URL) {
                return $this->tokenResponse();
            }

            $snapshotCalls++;

            // Success, failure, success.
            if ($snapshotCalls === 2) {
                return Http::response(['error' => 'down'], 503);
            }

            return Http::response(
                ['version' => self::VERSION_1, 'rules' => $this->defaultRules()],
                200,
                ['ETag' => '"'.self::VERSION_1.'"'],
            );
        });
        Log::shouldReceive('warning');

        $enforcer = $this->app->make(AuthzEnforcer::class);
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));

        $this->travel(31)->seconds();
        $enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET');
        $this->assertSame(1, $enforcer->status()['consecutive_failures']);

        // Past the 5 s window: refresh succeeds and resets the backoff.
        $this->travel(6)->seconds();
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));

        $status = $enforcer->status();
        $this->assertSame(0, $status['consecutive_failures']);
        $this->assertNull($status['last_error_at']);
        $this->assertNull($status['next_attempt_at']);
    }

    public function test_no_snapshot_inside_window_throws_without_request(): void
    {
        $snapshotCalls = 0;
        $this->fakeSuccessThenFailures($snapshotCalls, successes: 0);
        Log::shouldReceive('warning');

        $enforcer = $this->app->make(AuthzEnforcer::class);

        try {
            $enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET');
            $this->fail('Expected PolicyUnavailableException.');
        } catch (PolicyUnavailableException) {
        }

        $this->assertSame(1, $snapshotCalls);

        // Inside the window: throws immediately, no network call.
        $this->travel(2)->seconds();

        try {
            $enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET');
            $this->fail('Expected PolicyUnavailableException.');
        } catch (PolicyUnavailableException) {
        }

        $this->assertSame(1, $snapshotCalls);

        // Past the window: a new attempt is made (and fails again).
        $this->travel(4)->seconds();

        try {
            $enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET');
            $this->fail('Expected PolicyUnavailableException.');
        } catch (PolicyUnavailableException) {
        }

        $this->assertSame(2, $snapshotCalls);
    }

    public function test_status_exposes_health_fields(): void
    {
        $snapshotCalls = 0;
        $this->fakeSuccessThenFailures($snapshotCalls);
        Log::shouldReceive('warning');

        $enforcer = $this->app->make(AuthzEnforcer::class);

        // No snapshot yet.
        $status = $enforcer->status();
        $this->assertSame('http', $status['source']);
        $this->assertNull($status['version']);
        $this->assertNull($status['loaded_at']);
        $this->assertNull($status['age_seconds']);
        $this->assertNull($status['last_error_at']);
        $this->assertSame(0, $status['consecutive_failures']);
        $this->assertNull($status['next_attempt_at']);

        // Healthy snapshot.
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));

        $status = $enforcer->status();
        $this->assertSame('http', $status['source']);
        $this->assertSame(self::VERSION_1, $status['version']);
        $this->assertIsInt($status['loaded_at']);
        $this->assertSame(0, $status['age_seconds']);
        $this->assertNull($status['last_error_at']);
        $this->assertSame(0, $status['consecutive_failures']);
        $this->assertNull($status['next_attempt_at']);

        // After a failed refresh.
        $this->travel(31)->seconds();
        $enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET');

        $status = $enforcer->status();
        $this->assertSame(31, $status['age_seconds']);
        $this->assertIsInt($status['last_error_at']);
        $this->assertSame(1, $status['consecutive_failures']);
        $this->assertSame($status['last_error_at'] + 5, $status['next_attempt_at']);
    }

    public function test_database_source_backoff_skips_db_attempts_inside_window(): void
    {
        // Rebind to the default database source for this test.
        $this->app['config']->set('casbin-authz.source', 'database');
        Log::shouldReceive('warning');

        $this->seedDefaultPolicy();

        $enforcer = $this->app->make(AuthzEnforcer::class);
        $this->assertFalse($enforcer->allows('87654321', 'sistrans', '/api/tuc/123', 'GET'));

        // Stale + DB down: failure recorded, stale snapshot served.
        $this->travel(31)->seconds();
        $this->dropPolicyTable();
        $this->assertTrue($enforcer->allows('12345678', 'sistrans', '/api/tuc/123', 'GET'));

        // DB recovers with a new grant, but we are inside the backoff window:
        // no refresh attempt, so the new grant is not visible yet.
        $this->recreatePolicyTable();
        $this->seedDefaultPolicy();
        $this->insertRule('g', '87654321', 'operador', 'sistrans');

        $this->travel(2)->seconds();
        $this->assertFalse($enforcer->allows('87654321', 'sistrans', '/api/tuc/123', 'GET'));

        // Past the window: refresh succeeds and the grant appears.
        $this->travel(4)->seconds();
        $this->assertTrue($enforcer->allows('87654321', 'sistrans', '/api/tuc/123', 'GET'));
    }
}
