<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Support;

use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;

/**
 * RFC 4648 §5 base64url (URL-safe alphabet, no padding).
 */
final class Base64Url
{
    public static function encode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    /**
     * Decode a base64url string, rejecting any character outside the alphabet.
     *
     * @throws InvalidClientData
     */
    public static function decode(string $value): string
    {
        if ($value === '') {
            return '';
        }

        if (preg_match('/[^A-Za-z0-9_-]/', $value) === 1) {
            throw InvalidClientData::malformed();
        }

        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        if ($decoded === false) {
            throw InvalidClientData::malformed();
        }

        return $decoded;
    }
}
