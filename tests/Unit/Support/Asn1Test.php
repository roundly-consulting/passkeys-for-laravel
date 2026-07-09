<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Exceptions\InvalidCoseKey;
use RoundlyConsulting\Passkeys\Exceptions\SignatureInvalid;
use RoundlyConsulting\Passkeys\Support\Asn1;
use RoundlyConsulting\Passkeys\Tests\Support\TestKeys;

it('assembles an EC public key PEM openssl can load', function (): void {
    $key = TestKeys::ec();
    $details = openssl_pkey_get_details($key);
    $point = "\x04".str_pad($details['ec']['x'], 32, "\x00", STR_PAD_LEFT).str_pad($details['ec']['y'], 32, "\x00", STR_PAD_LEFT);

    $pem = Asn1::ecPublicKeyPem($point);

    expect($pem)->toContain('BEGIN PUBLIC KEY');
    expect(openssl_pkey_get_public($pem))->not->toBeFalse();
});

it('assembles an RSA public key PEM openssl can load', function (): void {
    $key = TestKeys::rsa();
    $details = openssl_pkey_get_details($key);

    $pem = Asn1::rsaPublicKeyPem($details['rsa']['n'], $details['rsa']['e']);

    expect(openssl_pkey_get_public($pem))->not->toBeFalse();
});

it('handles an RSA modulus whose high bit is set (leading zero rule)', function (): void {
    // A modulus with the top bit set must gain a 0x00 prefix to stay positive.
    $modulus = "\xff".random_bytes(255);
    $pem = Asn1::rsaPublicKeyPem($modulus, "\x01\x00\x01");

    expect(openssl_pkey_get_public($pem))->not->toBeFalse();
});

it('converts a raw 64-byte ECDSA signature into valid DER', function (): void {
    $raw = str_repeat("\x7f", 32).str_repeat("\x01", 32);

    $der = Asn1::ecdsaRawToDer($raw);

    expect(Asn1::isValidEcdsaDer($der))->toBeTrue();
});

it('prefixes a high-bit r/s value with a zero byte in DER', function (): void {
    $raw = str_repeat("\xff", 32).str_repeat("\xff", 32);

    $der = Asn1::ecdsaRawToDer($raw);

    expect(Asn1::isValidEcdsaDer($der))->toBeTrue();
});

it('rejects a raw signature of the wrong length', function (): void {
    Asn1::ecdsaRawToDer(str_repeat("\x01", 40));
})->throws(SignatureInvalid::class);

it('validates a genuine ECDSA DER signature', function (): void {
    $key = TestKeys::ec();
    openssl_sign('payload', $signature, $key, OPENSSL_ALGO_SHA256);

    expect(Asn1::isValidEcdsaDer($signature))->toBeTrue();
});

it('rejects DER that is not a sequence', function (): void {
    expect(Asn1::isValidEcdsaDer("\x02\x01\x01\x02\x01\x01\x00\x00"))->toBeFalse();
});

it('rejects DER shorter than the minimum', function (): void {
    expect(Asn1::isValidEcdsaDer("\x30\x02\x02\x01"))->toBeFalse();
});

it('rejects DER whose declared sequence length is wrong', function (): void {
    // SEQUENCE claims length 2 but the body is longer.
    expect(Asn1::isValidEcdsaDer("\x30\x02\x02\x01\x01\x02\x01\x01"))->toBeFalse();
});

it('rejects a non-minimally-encoded integer', function (): void {
    // r encoded as 00 01 (leading zero without a following high bit) is not minimal.
    $der = "\x30\x08\x02\x02\x00\x01\x02\x02\x00\x01";
    expect(Asn1::isValidEcdsaDer($der))->toBeFalse();
});

it('rejects a negative integer (high bit set without a zero prefix)', function (): void {
    $der = "\x30\x06\x02\x01\x80\x02\x01\x01";
    expect(Asn1::isValidEcdsaDer($der))->toBeFalse();
});

it('accepts a DER sequence that uses long-form length encoding', function (): void {
    $body = "\x02\x02\x01\x02\x02\x02\x01\x02"; // two minimal 2-byte integers
    $der = "\x30\x81\x08".$body;

    expect(Asn1::isValidEcdsaDer($der))->toBeTrue();
});

it('rejects DER whose length uses too many bytes', function (): void {
    // 0x85 => a 5-byte long-form length, which exceeds the supported cap.
    expect(Asn1::isValidEcdsaDer("\x30\x85\x00\x00\x00\x00\x08\x02\x01\x01"))->toBeFalse();
});

it('rejects DER with a zero-count long-form length', function (): void {
    // 0x80 => indefinite/zero-count length, never valid here.
    expect(Asn1::isValidEcdsaDer("\x30\x80\x02\x01\x01\x02\x01\x01"))->toBeFalse();
});

it('rejects DER that ends before the second integer', function (): void {
    // A single 6-byte integer fills the sequence, leaving no room for s.
    expect(Asn1::isValidEcdsaDer("\x30\x08\x02\x06\x01\x02\x03\x04\x05\x06"))->toBeFalse();
});

it('rejects DER with a zero-length integer', function (): void {
    expect(Asn1::isValidEcdsaDer("\x30\x04\x02\x00\x02\x01\x01"))->toBeFalse();
});

it('rejects DER whose second element is not an integer', function (): void {
    expect(Asn1::isValidEcdsaDer("\x30\x06\x02\x01\x01\x03\x01\x01"))->toBeFalse();
});

it('requires binary of an exact length', function (): void {
    expect(Asn1::requireBinary('abcd', 4, 'x'))->toBe('abcd');
});

it('rejects binary of an unexpected length', function (): void {
    Asn1::requireBinary('abc', 4, 'x');
})->throws(InvalidCoseKey::class);
