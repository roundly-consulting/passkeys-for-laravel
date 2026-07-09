<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Support;

use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * Generates OpenSSL key pairs for the test vectors. On some platforms (notably
 * Homebrew macOS) openssl_pkey_new cannot find a default openssl.cnf and refuses
 * to generate EC keys; when a config is discoverable it is passed explicitly. On
 * CI (Linux) no candidate matches and OpenSSL uses its built-in defaults.
 */
final class TestKeys
{
    public static function ec(): OpenSSLAsymmetricKey
    {
        return self::make([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
    }

    public static function rsa(int $bits = 2048): OpenSSLAsymmetricKey
    {
        return self::make([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => $bits,
        ]);
    }

    /**
     * @param  array<string, mixed>  $options
     */
    private static function make(array $options): OpenSSLAsymmetricKey
    {
        $config = self::config();

        if ($config !== null) {
            $options['config'] = $config;
        }

        $key = openssl_pkey_new($options);

        if ($key === false) {
            throw new RuntimeException('Unable to generate an OpenSSL key pair for the test vectors.');
        }

        return $key;
    }

    private static function config(): ?string
    {
        $candidates = [
            getenv('OPENSSL_CONF') ?: null,
            '/opt/homebrew/etc/openssl@3/openssl.cnf',
            '/usr/local/etc/openssl@3/openssl.cnf',
            '/opt/homebrew/etc/openssl@1.1/openssl.cnf',
        ];

        foreach ($candidates as $candidate) {
            if (is_string($candidate) && is_file($candidate)) {
                return $candidate;
            }
        }

        return null;
    }
}
