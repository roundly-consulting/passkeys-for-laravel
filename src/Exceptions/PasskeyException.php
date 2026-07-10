<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

use RuntimeException;

/**
 * Base type for every passkey ceremony failure. Hosts may catch this broadly,
 * or catch any of the typed children for finer control.
 *
 * Messages are resolved through the package translation namespace so hosts can
 * localise them (`resources/lang/vendor/passkeys/<locale>/errors.php`).
 */
abstract class PasskeyException extends RuntimeException
{
    /**
     * @param  array<string, string>  $replace
     */
    protected static function trans(string $key, array $replace = []): string
    {
        $line = __('passkeys::errors.'.$key, $replace);

        return is_string($line) ? $line : $key;
    }
}
