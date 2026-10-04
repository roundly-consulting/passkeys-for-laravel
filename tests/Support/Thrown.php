<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Support;

use RuntimeException;
use Throwable;

final class Thrown
{
    /**
     * The exception the callback throws, so a test can hold its message, previous
     * exception and context to account — failing when it throws nothing.
     */
    public static function by(callable $callback): Throwable
    {
        try {
            $callback();
        } catch (Throwable $e) {
            return $e;
        }

        throw new RuntimeException('Expected an exception, but none was thrown.');
    }
}
