<?php

declare(strict_types=1);

namespace Muni\CasbinAuthz;

use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use RuntimeException;

/**
 * Pulls the policy snapshot from the control plane over HTTPS
 * (GET /policies/snapshot), authenticating via Hydra client_credentials
 * with scope authz.read.
 */
class HttpPolicySource
{
    private const TOKEN_CACHE_KEY = 'casbin-authz:access-token';

    private const TOKEN_EXPIRY_MARGIN_SECONDS = 30;

    public function __construct(
        private readonly string $snapshotUrl,
        private readonly string $tokenUrl,
        private readonly string $clientId,
        private readonly string $clientSecret,
        private readonly string $scope,
        private readonly int $timeoutSeconds,
    ) {
    }

    /**
     * Fetch the snapshot, sending If-None-Match for the stored version.
     *
     * @return array{not_modified: bool, version: string, rules: array<int, array<int, string>>|null}
     *
     * @throws RuntimeException on any failure (token error, HTTP error, malformed body)
     */
    public function fetch(?string $currentVersion): array
    {
        $response = $this->requestSnapshot($this->accessToken(), $currentVersion);

        if ($response->status() === 401) {
            // Token may have been revoked/expired early: fetch a new one and retry once.
            Cache::forget(self::TOKEN_CACHE_KEY);
            $response = $this->requestSnapshot($this->accessToken(), $currentVersion);
        }

        if ($response->status() === 304) {
            if ($currentVersion === null) {
                throw new RuntimeException('casbin-authz: snapshot endpoint returned 304 without a stored version.');
            }

            return ['not_modified' => true, 'version' => $currentVersion, 'rules' => null];
        }

        if (! $response->successful()) {
            throw new RuntimeException(sprintf('casbin-authz: snapshot request failed with HTTP %d.', $response->status()));
        }

        return $this->parseBody($response);
    }

    private function requestSnapshot(string $token, ?string $currentVersion): Response
    {
        $request = Http::timeout($this->timeoutSeconds)
            ->withToken($token)
            // Ask for gzip; Guzzle's curl handler decodes it (decode_content defaults to true).
            ->withHeaders(['Accept-Encoding' => 'gzip'])
            ->acceptJson();

        if ($currentVersion !== null) {
            $request = $request->withHeaders(['If-None-Match' => '"'.$currentVersion.'"']);
        }

        return $request->get($this->snapshotUrl);
    }

    /**
     * Access token via client_credentials (client_secret_post), cached until
     * 30 s before expires_in.
     */
    private function accessToken(): string
    {
        $cached = Cache::get(self::TOKEN_CACHE_KEY);

        if (is_string($cached) && $cached !== '') {
            return $cached;
        }

        $response = Http::asForm()
            ->timeout($this->timeoutSeconds)
            ->post($this->tokenUrl, [
                'grant_type' => 'client_credentials',
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'scope' => $this->scope,
            ]);

        if (! $response->successful()) {
            throw new RuntimeException(sprintf('casbin-authz: token request failed with HTTP %d.', $response->status()));
        }

        $token = $response->json('access_token');

        if (! is_string($token) || $token === '') {
            throw new RuntimeException('casbin-authz: token response did not contain an access_token.');
        }

        $ttl = (int) $response->json('expires_in', 0) - self::TOKEN_EXPIRY_MARGIN_SECONDS;

        if ($ttl > 0) {
            Cache::put(self::TOKEN_CACHE_KEY, $token, $ttl);
        }

        return $token;
    }

    /**
     * @return array{not_modified: bool, version: string, rules: array<int, array<int, string>>}
     */
    private function parseBody(Response $response): array
    {
        $body = $response->json();

        if (! is_array($body)
            || ! isset($body['version'], $body['rules'])
            || ! is_string($body['version'])
            || $body['version'] === ''
            || ! is_array($body['rules'])
        ) {
            throw new RuntimeException('casbin-authz: malformed snapshot body (expected {version, rules}).');
        }

        $rules = [];

        foreach ($body['rules'] as $rule) {
            if (! is_array($rule) || $rule === []) {
                throw new RuntimeException('casbin-authz: malformed snapshot rule (expected non-empty array).');
            }

            $values = array_values($rule);

            foreach ($values as $value) {
                if (! is_string($value)) {
                    throw new RuntimeException('casbin-authz: malformed snapshot rule value (expected string).');
                }
            }

            if (preg_match('/^[pg][0-9]*$/', $values[0]) !== 1) {
                throw new RuntimeException('casbin-authz: malformed snapshot rule (expected a ptype first).');
            }

            $rules[] = $values;
        }

        return ['not_modified' => false, 'version' => $body['version'], 'rules' => $rules];
    }
}
