<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\DataTransferObjects\CoseKeyData;
use RoundlyConsulting\Passkeys\Enums\CoseAlgorithm;
use RoundlyConsulting\Passkeys\Exceptions\UnsupportedAlgorithm;
use RoundlyConsulting\Passkeys\Support\Asn1;
use RoundlyConsulting\Passkeys\Support\CborDecoder;
use RoundlyConsulting\Passkeys\Support\CoseKey;
use RoundlyConsulting\Passkeys\Support\SignatureVerifier;
use RoundlyConsulting\Passkeys\Tests\Support\TestKeys;

beforeEach(function (): void {
    $this->verifier = new SignatureVerifier;
    $this->coseKey = new CoseKey;
    $this->cbor = new CborDecoder;
});

/**
 * @return array{0: CoseKeyData, 1: OpenSSLAsymmetricKey}
 */
function es256KeyPair(CoseKey $parser, CborDecoder $cbor): array
{
    $private = TestKeys::ec();
    $details = openssl_pkey_get_details($private);

    $point = "\x04".str_pad($details['ec']['x'], 32, "\x00", STR_PAD_LEFT).str_pad($details['ec']['y'], 32, "\x00", STR_PAD_LEFT);

    return [new CoseKeyData(algorithm: CoseAlgorithm::ES256, pem: Asn1::ecPublicKeyPem($point)), $private];
}

it('verifies a valid ES256 DER signature', function (): void {
    [$key, $private] = es256KeyPair($this->coseKey, $this->cbor);
    openssl_sign('message', $signature, $private, OPENSSL_ALGO_SHA256);

    expect($this->verifier->verify($key, 'message', $signature))->toBeTrue();
});

it('verifies a valid ES256 signature delivered as raw r‖s', function (): void {
    [$key, $private] = es256KeyPair($this->coseKey, $this->cbor);
    openssl_sign('message', $der, $private, OPENSSL_ALGO_SHA256);

    // Re-shape DER into raw form the way some authenticators emit it, then verify.
    $raw = ecdsaDerToRaw($der);

    expect($this->verifier->verify($key, 'message', $raw))->toBeTrue();
});

it('rejects a tampered ES256 signature', function (): void {
    [$key, $private] = es256KeyPair($this->coseKey, $this->cbor);
    openssl_sign('message', $signature, $private, OPENSSL_ALGO_SHA256);
    $signature[10] = $signature[10] === "\x00" ? "\x01" : "\x00";

    expect($this->verifier->verify($key, 'message', $signature))->toBeFalse();
});

it('rejects an ES256 signature that is neither valid DER nor 64 raw bytes', function (): void {
    [$key] = es256KeyPair($this->coseKey, $this->cbor);

    expect($this->verifier->verify($key, 'message', 'garbage'))->toBeFalse();
});

it('rejects an ES256 signature against a different key', function (): void {
    [$key] = es256KeyPair($this->coseKey, $this->cbor);
    [, $other] = es256KeyPair($this->coseKey, $this->cbor);
    openssl_sign('message', $signature, $other, OPENSSL_ALGO_SHA256);

    expect($this->verifier->verify($key, 'message', $signature))->toBeFalse();
});

it('treats an openssl error (-1) from a broken PEM as a failure', function (): void {
    $key = new CoseKeyData(algorithm: CoseAlgorithm::ES256, pem: "-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----\n");
    $raw = str_repeat("\x01", 64);

    expect($this->verifier->verify($key, 'message', $raw))->toBeFalse();
});

it('fails when the key has no PEM material', function (): void {
    $key = new CoseKeyData(algorithm: CoseAlgorithm::RS256, pem: null);

    expect($this->verifier->verify($key, 'message', str_repeat("\x01", 64)))->toBeFalse();
});

it('verifies a valid RS256 signature and rejects a tampered one', function (): void {
    $private = TestKeys::rsa();
    $details = openssl_pkey_get_details($private);
    $key = new CoseKeyData(algorithm: CoseAlgorithm::RS256, pem: Asn1::rsaPublicKeyPem($details['rsa']['n'], $details['rsa']['e']));

    openssl_sign('message', $signature, $private, OPENSSL_ALGO_SHA256);
    expect($this->verifier->verify($key, 'message', $signature))->toBeTrue();

    $signature[5] = $signature[5] === "\x00" ? "\x01" : "\x00";
    expect($this->verifier->verify($key, 'message', $signature))->toBeFalse();
});

it('throws when Ed25519 verification is requested without ext-sodium', function (): void {
    if (function_exists('sodium_crypto_sign_verify_detached')) {
        $this->markTestSkipped('ext-sodium is loaded; the unsupported path cannot be exercised.');
    }

    $key = new CoseKeyData(algorithm: CoseAlgorithm::EdDSA, edwardsPublicKey: str_repeat("\x01", 32));
    $this->verifier->verify($key, 'message', str_repeat("\x02", 64));
})->throws(UnsupportedAlgorithm::class);

it('verifies an Ed25519 signature when ext-sodium is available', function (): void {
    if (! function_exists('sodium_crypto_sign_verify_detached')) {
        $this->markTestSkipped('ext-sodium is not loaded.');
    }

    $pair = sodium_crypto_sign_keypair();
    $public = sodium_crypto_sign_publickey($pair);
    $secret = sodium_crypto_sign_secretkey($pair);
    $signature = sodium_crypto_sign_detached('message', $secret);

    $key = new CoseKeyData(algorithm: CoseAlgorithm::EdDSA, edwardsPublicKey: $public);

    expect($this->verifier->verify($key, 'message', $signature))->toBeTrue()
        ->and($this->verifier->verify($key, 'tampered', $signature))->toBeFalse();
});

it('rejects an Ed25519 signature of the wrong length', function (): void {
    if (! function_exists('sodium_crypto_sign_verify_detached')) {
        $this->markTestSkipped('ext-sodium is not loaded.');
    }

    $key = new CoseKeyData(algorithm: CoseAlgorithm::EdDSA, edwardsPublicKey: str_repeat("\x01", 32));

    expect($this->verifier->verify($key, 'message', str_repeat("\x02", 10)))->toBeFalse();
});

/**
 * Local DER -> raw r‖s helper for the "raw signature" verification test.
 */
function ecdsaDerToRaw(string $der): string
{
    $offset = 2;
    if ($der[1] === "\x81") {
        $offset = 3;
    }

    $offset++; // INTEGER tag
    $rLen = ord($der[$offset++]);
    $r = ltrim(substr($der, $offset, $rLen), "\x00");
    $offset += $rLen;

    $offset++; // INTEGER tag
    $sLen = ord($der[$offset++]);
    $s = ltrim(substr($der, $offset, $sLen), "\x00");

    return str_pad($r, 32, "\x00", STR_PAD_LEFT).str_pad($s, 32, "\x00", STR_PAD_LEFT);
}
