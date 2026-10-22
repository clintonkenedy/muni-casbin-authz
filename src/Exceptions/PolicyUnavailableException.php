<?php

declare(strict_types=1);

namespace Muni\CasbinAuthz\Exceptions;

use RuntimeException;

/**
 * Thrown when no policy snapshot exists and the database cannot be reached.
 * Consumers should map this to a 503 response (authorization unavailable).
 */
class PolicyUnavailableException extends RuntimeException
{
}
