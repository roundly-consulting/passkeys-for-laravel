<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Testing;

/**
 * A tiny, TEST-ONLY CBOR encoder behind {@see VirtualAuthenticator} and the package's
 * own test vectors: it builds the attestation objects and COSE keys an authenticator
 * would send. The relying party itself never encodes CBOR (it only decodes, through
 * crypto-for-laravel), so nothing in production calls this. It lives in runtime
 * autoload only so consuming packages' suites can reach it — the same posture as
 * {@see PasskeysFake}. Supports only the subset the fixtures need.
 */
final class CborEncoder
{
    public static function uint(int $value): string
    {
        return self::head(0, $value);
    }

    public static function nint(int $value): string
    {
        // Encodes a negative integer n as major type 1 with argument (-1 - n).
        return self::head(1, -1 - $value);
    }

    public static function bstr(string $bytes): string
    {
        return self::head(2, strlen($bytes)).$bytes;
    }

    public static function tstr(string $text): string
    {
        return self::head(3, strlen($text)).$text;
    }

    /**
     * @param  list<string>  $items  already-encoded items
     */
    public static function arr(array $items): string
    {
        return self::head(4, count($items)).implode('', $items);
    }

    /**
     * @param  array<int, array{0: string, 1: string}>  $pairs  encoded [key, value] pairs
     */
    public static function map(array $pairs): string
    {
        $body = '';

        foreach ($pairs as [$key, $value]) {
            $body .= $key.$value;
        }

        return self::head(5, count($pairs)).$body;
    }

    public static function simple(bool $value): string
    {
        return chr((7 << 5) | ($value ? 21 : 20));
    }

    private static function head(int $major, int $value): string
    {
        $prefix = $major << 5;

        return match (true) {
            $value < 24 => chr($prefix | $value),
            $value < 0x100 => chr($prefix | 24).chr($value),
            $value < 0x10000 => chr($prefix | 25).pack('n', $value),
            $value < 0x100000000 => chr($prefix | 26).pack('N', $value),
            default => chr($prefix | 27).pack('J', $value),
        };
    }
}
