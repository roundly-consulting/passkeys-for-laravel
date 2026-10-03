<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Support;

use RoundlyConsulting\PackageToolkit\Support\Config;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\Exceptions\InvalidConfiguration;

/**
 * Strict readers for the few `passkeys.*` settings read outside {@see PasskeyConfig}
 * (the table, the user-handle column and the host model's attribute names). Callers read
 * the value with a literal `config()` and hand it in, so the key stays visible to the
 * config contract.
 *
 * @internal the package's own config wiring — hosts configure `config/passkeys.php`.
 */
final class StrictConfig
{
    /**
     * A required string: `$default` only when absent (null); a blank or non-string value
     * throws {@see InvalidConfiguration} instead of silently reading as the default.
     *
     * @param  string  $key  the key under `passkeys.`, for the message
     *
     * @throws InvalidConfiguration
     */
    public static function string(string $key, mixed $value, string $default): string
    {
        $value ??= $default;

        if (! is_string($value) || trim($value) === '') {
            throw InvalidConfiguration::invalidValue($key, 'a non-empty string', $value);
        }

        return $value;
    }

    /**
     * An int or a canonical integer string within the bounds; `$default` only when absent.
     *
     * @param  string  $key  the key under `passkeys.`, for the message
     *
     * @throws InvalidConfiguration
     */
    public static function integer(string $key, mixed $value, int $default, ?int $min = null, ?int $max = null): int
    {
        return Config::for(["passkeys.{$key}" => $value], InvalidConfiguration::class)->integer("passkeys.{$key}", $default, $min, $max);
    }
}
