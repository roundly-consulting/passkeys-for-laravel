<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Support;

use RoundlyConsulting\Passkeys\Exceptions\InvalidCoseKey;
use RoundlyConsulting\Passkeys\Exceptions\SignatureInvalid;

/**
 * Minimal ASN.1/DER assembly. Builds SubjectPublicKeyInfo (SPKI) PEM material
 * for EC2 (P-256) and RSA COSE keys so ext-openssl can verify signatures, and
 * converts P-256 ECDSA signatures between the raw r‖s form WebAuthn/COSE deliver
 * and the DER SEQUENCE(INTEGER, INTEGER) form OpenSSL expects.
 */
final class Asn1
{
    // Pre-encoded DER for the algorithm-identifier OIDs (fixed byte templates).
    private const OID_EC_PUBLIC_KEY = "\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01";

    private const OID_PRIME256V1 = "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07";

    private const OID_RSA_ENCRYPTION = "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01";

    private const DER_NULL = "\x05\x00";

    /**
     * Assemble an EC (prime256v1) public key PEM from a 65-byte uncompressed point.
     */
    public static function ecPublicKeyPem(string $uncompressedPoint): string
    {
        $algorithm = self::sequence(self::OID_EC_PUBLIC_KEY.self::OID_PRIME256V1);
        $spki = self::sequence($algorithm.self::bitString($uncompressedPoint));

        return self::pem($spki, 'PUBLIC KEY');
    }

    /**
     * Assemble an RSA public key PEM from raw modulus and exponent bytes.
     */
    public static function rsaPublicKeyPem(string $modulus, string $exponent): string
    {
        $rsaKey = self::sequence(self::integer($modulus).self::integer($exponent));
        $algorithm = self::sequence(self::OID_RSA_ENCRYPTION.self::DER_NULL);
        $spki = self::sequence($algorithm.self::bitString($rsaKey));

        return self::pem($spki, 'PUBLIC KEY');
    }

    /**
     * Convert a raw 64-byte P-256 ECDSA signature (r‖s) to DER.
     *
     * @throws SignatureInvalid
     */
    public static function ecdsaRawToDer(string $raw): string
    {
        if (strlen($raw) !== 64) {
            throw SignatureInvalid::make();
        }

        $r = self::integer(substr($raw, 0, 32));
        $s = self::integer(substr($raw, 32, 32));

        return self::sequence($r.$s);
    }

    /**
     * Validate that a byte string is a well-formed ECDSA DER signature:
     * SEQUENCE { INTEGER r, INTEGER s }, minimally encoded, nothing trailing.
     */
    public static function isValidEcdsaDer(string $der): bool
    {
        $length = strlen($der);

        if ($length < 8 || $der[0] !== "\x30") {
            return false;
        }

        $offset = 1;
        $seqLen = self::readDerLength($der, $offset);

        if ($seqLen === null || $offset + $seqLen !== $length) {
            return false;
        }

        foreach ([0, 1] as $ignored) {
            if ($offset >= $length || $der[$offset] !== "\x02") {
                return false;
            }

            $offset++;
            $intLen = self::readDerLength($der, $offset);

            if ($intLen === null || $intLen < 1 || $offset + $intLen > $length) {
                return false;
            }

            if (! self::isMinimalInteger(substr($der, $offset, $intLen))) {
                return false;
            }

            $offset += $intLen;
        }

        return $offset === $length;
    }

    private static function isMinimalInteger(string $content): bool
    {
        // A leading 0x00 is only allowed to keep a high-bit-set value positive.
        if ($content[0] === "\x00") {
            return strlen($content) > 1 && (ord($content[1]) & 0x80) !== 0;
        }

        // A negative integer (high bit set) is never valid for r/s.
        return (ord($content[0]) & 0x80) === 0;
    }

    private static function readDerLength(string $der, int &$offset): ?int
    {
        if ($offset >= strlen($der)) {
            return null;
        }

        $first = ord($der[$offset++]);

        if ($first < 0x80) {
            return $first;
        }

        $count = $first & 0x7F;

        if ($count === 0 || $count > 4 || $offset + $count > strlen($der)) {
            return null;
        }

        $value = 0;

        for ($i = 0; $i < $count; $i++) {
            $value = ($value << 8) | ord($der[$offset++]);
        }

        return $value;
    }

    private static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");

        if ($bytes === '') {
            $bytes = "\x00";
        }

        // Prepend a zero byte when the high bit is set to keep the value positive.
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00".$bytes;
        }

        return "\x02".self::length($bytes).$bytes;
    }

    private static function sequence(string $content): string
    {
        return "\x30".self::length($content).$content;
    }

    private static function bitString(string $content): string
    {
        // Leading 0x00 = number of unused bits in the final byte (always zero here).
        $content = "\x00".$content;

        return "\x03".self::length($content).$content;
    }

    private static function length(string $content): string
    {
        $length = strlen($content);

        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';

        while ($length > 0) {
            $bytes = chr($length & 0xFF).$bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes)).$bytes;
    }

    private static function pem(string $der, string $label): string
    {
        $base64 = chunk_split(base64_encode($der), 64, "\n");

        return "-----BEGIN {$label}-----\n{$base64}-----END {$label}-----\n";
    }

    /**
     * Guard used by callers that need an SPKI PEM but only have the raw parts.
     *
     * @throws InvalidCoseKey
     */
    public static function requireBinary(string $value, int $length, string $field): string
    {
        if (strlen($value) !== $length) {
            throw InvalidCoseKey::make($field.' must be '.$length.' bytes');
        }

        return $value;
    }
}
