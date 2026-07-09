<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Support;

use RoundlyConsulting\Passkeys\DataTransferObjects\CoseKeyData;
use RoundlyConsulting\Passkeys\Enums\CoseAlgorithm;
use RoundlyConsulting\Passkeys\Exceptions\InvalidCoseKey;
use RoundlyConsulting\Passkeys\Exceptions\UnsupportedAlgorithm;

/**
 * Turns a decoded COSE_Key map into verification material.
 *
 * COSE_Key labels used here (RFC 9052 / RFC 9053):
 *   1 = kty, 3 = alg, -1 = crv (EC/OKP) or n (RSA), -2 = x or e (RSA), -3 = y.
 * kty: 1 = OKP, 2 = EC2, 3 = RSA. crv: 1 = P-256, 6 = Ed25519.
 */
final class CoseKey
{
    /**
     * @param  array<int|string, mixed>  $decoded
     *
     * @throws InvalidCoseKey|UnsupportedAlgorithm
     */
    public function fromDecoded(array $decoded): CoseKeyData
    {
        $kty = $this->int($decoded, 1, 'kty');
        $algorithm = $this->algorithm($decoded);

        return match ($kty) {
            2 => $this->ec2($decoded, $algorithm),
            3 => $this->rsa($decoded, $algorithm),
            1 => $this->okp($decoded, $algorithm),
            default => throw InvalidCoseKey::make('unsupported key type '.$kty),
        };
    }

    /**
     * @param  array<int|string, mixed>  $decoded
     */
    private function ec2(array $decoded, CoseAlgorithm $algorithm): CoseKeyData
    {
        if ($algorithm !== CoseAlgorithm::ES256) {
            throw InvalidCoseKey::make('EC2 key must use ES256');
        }

        if ($this->int($decoded, -1, 'crv') !== 1) {
            throw InvalidCoseKey::make('EC2 key must use the P-256 curve');
        }

        $x = Asn1::requireBinary($this->bytes($decoded, -2, 'x'), 32, 'x');
        $y = Asn1::requireBinary($this->bytes($decoded, -3, 'y'), 32, 'y');

        return new CoseKeyData(
            algorithm: $algorithm,
            pem: Asn1::ecPublicKeyPem("\x04".$x.$y),
        );
    }

    /**
     * @param  array<int|string, mixed>  $decoded
     */
    private function rsa(array $decoded, CoseAlgorithm $algorithm): CoseKeyData
    {
        if ($algorithm !== CoseAlgorithm::RS256) {
            throw InvalidCoseKey::make('RSA key must use RS256');
        }

        $modulus = $this->bytes($decoded, -1, 'n');
        $exponent = $this->bytes($decoded, -2, 'e');

        if ($modulus === '' || $exponent === '') {
            throw InvalidCoseKey::make('RSA modulus and exponent are required');
        }

        return new CoseKeyData(
            algorithm: $algorithm,
            pem: Asn1::rsaPublicKeyPem($modulus, $exponent),
        );
    }

    /**
     * @param  array<int|string, mixed>  $decoded
     */
    private function okp(array $decoded, CoseAlgorithm $algorithm): CoseKeyData
    {
        if ($algorithm !== CoseAlgorithm::EdDSA) {
            throw InvalidCoseKey::make('OKP key must use EdDSA');
        }

        if ($this->int($decoded, -1, 'crv') !== 6) {
            throw InvalidCoseKey::make('OKP key must use the Ed25519 curve');
        }

        $x = Asn1::requireBinary($this->bytes($decoded, -2, 'x'), 32, 'x');

        return new CoseKeyData(algorithm: $algorithm, edwardsPublicKey: $x);
    }

    /**
     * @param  array<int|string, mixed>  $decoded
     */
    private function algorithm(array $decoded): CoseAlgorithm
    {
        $alg = $this->int($decoded, 3, 'alg');

        return CoseAlgorithm::tryFrom($alg) ?? throw UnsupportedAlgorithm::forId($alg);
    }

    /**
     * @param  array<int|string, mixed>  $decoded
     */
    private function int(array $decoded, int $label, string $name): int
    {
        $value = $decoded[$label] ?? null;

        if (! is_int($value)) {
            throw InvalidCoseKey::make('missing or non-integer '.$name);
        }

        return $value;
    }

    /**
     * @param  array<int|string, mixed>  $decoded
     */
    private function bytes(array $decoded, int $label, string $name): string
    {
        $value = $decoded[$label] ?? null;

        if (! is_string($value)) {
            throw InvalidCoseKey::make('missing or non-binary '.$name);
        }

        return $value;
    }
}
