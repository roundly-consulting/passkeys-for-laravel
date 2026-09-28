<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

use RoundlyConsulting\Passkeys\Testing\PasskeysFake;

/**
 * Thrown by {@see PasskeysFake} when one of its assertions fails. It is a package
 * exception (not a PHPUnit assertion) so the fake stays runtime-only and works
 * under any test runner.
 */
final class PasskeyAssertionFailed extends PasskeyException
{
    public static function make(string $message): self
    {
        return new self($message);
    }
}
