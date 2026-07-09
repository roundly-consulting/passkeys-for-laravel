<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Enums\CoseAlgorithm;
use RoundlyConsulting\Passkeys\Exceptions\InvalidCoseKey;
use RoundlyConsulting\Passkeys\Exceptions\UnsupportedAlgorithm;
use RoundlyConsulting\Passkeys\Support\CborDecoder;
use RoundlyConsulting\Passkeys\Support\CoseKey;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

beforeEach(function (): void {
    $this->coseKey = new CoseKey;
    $this->cbor = new CborDecoder;
});

/**
 * @return array<int|string, mixed>
 */
function decodeCose(string $bytes): array
{
    $decoded = (new CborDecoder)->decode($bytes);

    expect($decoded)->toBeArray();

    /** @var array<int|string, mixed> $decoded */
    return $decoded;
}

it('parses a real ES256 EC2 key into an SPKI PEM', function (): void {
    $key = $this->coseKey->fromDecoded(decodeCose(WebAuthnVectors::es256()->coseKey()));

    expect($key->algorithm)->toBe(CoseAlgorithm::ES256)
        ->and($key->pem)->toContain('BEGIN PUBLIC KEY')
        ->and($key->edwardsPublicKey)->toBeNull();
});

it('parses a real RS256 RSA key into an SPKI PEM', function (): void {
    $key = $this->coseKey->fromDecoded(decodeCose(WebAuthnVectors::rs256()->coseKey()));

    expect($key->algorithm)->toBe(CoseAlgorithm::RS256)
        ->and($key->pem)->toContain('BEGIN PUBLIC KEY');
});

it('rejects an EC2 key that is not ES256', function (): void {
    $this->coseKey->fromDecoded([1 => 2, 3 => -257, -1 => 1, -2 => str_repeat('x', 32), -3 => str_repeat('y', 32)]);
})->throws(InvalidCoseKey::class);

it('rejects an EC2 key on the wrong curve', function (): void {
    $this->coseKey->fromDecoded([1 => 2, 3 => -7, -1 => 2, -2 => str_repeat('x', 32), -3 => str_repeat('y', 32)]);
})->throws(InvalidCoseKey::class);

it('rejects EC2 coordinates of the wrong length', function (): void {
    $this->coseKey->fromDecoded([1 => 2, 3 => -7, -1 => 1, -2 => 'short', -3 => str_repeat('y', 32)]);
})->throws(InvalidCoseKey::class);

it('rejects an RSA key that is not RS256', function (): void {
    $this->coseKey->fromDecoded([1 => 3, 3 => -7, -1 => str_repeat('n', 256), -2 => "\x01\x00\x01"]);
})->throws(InvalidCoseKey::class);

it('rejects an RSA key with an empty modulus', function (): void {
    $this->coseKey->fromDecoded([1 => 3, 3 => -257, -1 => '', -2 => "\x01\x00\x01"]);
})->throws(InvalidCoseKey::class);

it('rejects an unsupported key type', function (): void {
    $this->coseKey->fromDecoded([1 => 4, 3 => -7]);
})->throws(InvalidCoseKey::class);

it('rejects an unknown algorithm identifier', function (): void {
    $this->coseKey->fromDecoded([1 => 2, 3 => -999]);
})->throws(UnsupportedAlgorithm::class);

it('rejects a key missing its kty label', function (): void {
    $this->coseKey->fromDecoded([3 => -7]);
})->throws(InvalidCoseKey::class);

it('rejects a non-integer curve label', function (): void {
    $this->coseKey->fromDecoded([1 => 2, 3 => -7, -1 => 'p256', -2 => str_repeat('x', 32), -3 => str_repeat('y', 32)]);
})->throws(InvalidCoseKey::class);

it('rejects a non-binary coordinate', function (): void {
    $this->coseKey->fromDecoded([1 => 2, 3 => -7, -1 => 1, -2 => 5, -3 => str_repeat('y', 32)]);
})->throws(InvalidCoseKey::class);

it('parses an OKP Ed25519 key into a raw edwards key', function (): void {
    $key = $this->coseKey->fromDecoded([1 => 1, 3 => -8, -1 => 6, -2 => str_repeat("\x09", 32)]);

    expect($key->algorithm)->toBe(CoseAlgorithm::EdDSA)
        ->and($key->edwardsPublicKey)->toBe(str_repeat("\x09", 32))
        ->and($key->pem)->toBeNull();
});

it('rejects an OKP key that is not EdDSA', function (): void {
    $this->coseKey->fromDecoded([1 => 1, 3 => -7, -1 => 6, -2 => str_repeat("\x09", 32)]);
})->throws(InvalidCoseKey::class);

it('rejects an OKP key on the wrong curve', function (): void {
    $this->coseKey->fromDecoded([1 => 1, 3 => -8, -1 => 1, -2 => str_repeat("\x09", 32)]);
})->throws(InvalidCoseKey::class);
