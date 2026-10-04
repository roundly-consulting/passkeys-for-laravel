<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\CborDecoder;
use RoundlyConsulting\Crypto\Cose\UnsupportedAlgorithmException;
use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\InvalidSignatureException;
use RoundlyConsulting\Crypto\Signature\Key\PublicKey;
use RoundlyConsulting\Crypto\Signature\KeyVerifier;
use RoundlyConsulting\Crypto\Signature\Verifier;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAuthenticatorData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidCoseKey;
use RoundlyConsulting\Passkeys\Exceptions\MalformedCbor;
use RoundlyConsulting\Passkeys\Exceptions\SignatureInvalid;
use RoundlyConsulting\Passkeys\Exceptions\UnsupportedAlgorithm;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\CredentialCrypto;
use RoundlyConsulting\Passkeys\Testing\CborEncoder;
use RoundlyConsulting\Passkeys\Tests\Support\TestKeys;
use RoundlyConsulting\Passkeys\Tests\Support\Thrown;

/*
 * The crypto boundary. Every failure crypto can raise must arrive at the caller as
 * one of this package's own typed exceptions — a host never has to catch a
 * CryptoException, and no failure escapes untranslated.
 */

function crypto(): CredentialCrypto
{
    return new CredentialCrypto(new CborDecoder, new KeyVerifier);
}

function storedKey(string $base64): Passkey
{
    $passkey = new Passkey;
    $passkey->public_key = $base64;

    return $passkey;
}

/**
 * authenticatorData carrying an attested credential with the given COSE key.
 */
function attestedAuthData(string $coseKey): string
{
    return hash('sha256', 'example.com', true)  // rpIdHash
        .chr(0x45)                              // UP | UV | AT
        .pack('N', 0)                           // sign count
        .str_repeat("\x11", 16)                 // AAGUID
        .pack('n', 4).'cred'                    // credential id
        .$coseKey;
}

// --- attestationObject -------------------------------------------------------

it('translates malformed attestation CBOR', function (): void {
    crypto()->attestationObject("\xff\xff\xff");
})->throws(MalformedCbor::class);

it('rejects an attestation object that is not a map', function (): void {
    crypto()->attestationObject(CborEncoder::uint(7));
})->throws(InvalidClientData::class);

// --- authenticatorData -------------------------------------------------------

it('translates a truncated authenticator data structure', function (): void {
    crypto()->authenticatorData('too short');
})->throws(InvalidAuthenticatorData::class);

it('translates an unknown COSE algorithm on an attested key', function (): void {
    $cose = CborEncoder::map([
        [CborEncoder::uint(1), CborEncoder::uint(2)],       // kty: EC2
        [CborEncoder::nint(-999), CborEncoder::uint(1)],
        [CborEncoder::uint(3), CborEncoder::nint(-999)],    // alg: unknown
    ]);

    crypto()->authenticatorData(attestedAuthData($cose));
})->throws(UnsupportedAlgorithm::class);

it('translates an EC2 key with a malformed coordinate', function (): void {
    $cose = CborEncoder::map([
        [CborEncoder::uint(1), CborEncoder::uint(2)],       // kty: EC2
        [CborEncoder::uint(3), CborEncoder::nint(-7)],      // alg: ES256
        [CborEncoder::nint(-1), CborEncoder::uint(1)],      // crv: P-256
        [CborEncoder::nint(-2), CborEncoder::bstr(str_repeat("\x01", 31))], // x: 31 bytes
        [CborEncoder::nint(-3), CborEncoder::bstr(str_repeat("\x02", 32))],
    ]);

    crypto()->authenticatorData(attestedAuthData($cose));
})->throws(InvalidCoseKey::class);

it('rejects an RSA credential key below 2048 bits', function (): void {
    // crypto refuses a weak RSA modulus outright. Real authenticators mint RS256
    // credentials at 2048 bits, so this only ever fires on a key we should never
    // have trusted in the first place.
    $details = openssl_pkey_get_details(TestKeys::rsa(1024));

    $cose = CborEncoder::map([
        [CborEncoder::uint(1), CborEncoder::uint(3)],       // kty: RSA
        [CborEncoder::uint(3), CborEncoder::nint(-257)],    // alg: RS256
        [CborEncoder::nint(-1), CborEncoder::bstr($details['rsa']['n'])],
        [CborEncoder::nint(-2), CborEncoder::bstr($details['rsa']['e'])],
    ]);

    crypto()->authenticatorData(attestedAuthData($cose));
})->throws(InvalidCoseKey::class);

// --- storedPublicKey ---------------------------------------------------------

it('rejects a stored public key that is not padded base64', function (): void {
    crypto()->storedPublicKey(storedKey('@@ not base64 @@'));
})->throws(SignatureInvalid::class);

it('rejects a stored public key that is not CBOR', function (): void {
    crypto()->storedPublicKey(storedKey(base64_encode("\xff\xff\xff")));
})->throws(MalformedCbor::class);

it('rejects a stored public key that is not a COSE map', function (): void {
    crypto()->storedPublicKey(storedKey(base64_encode(CborEncoder::uint(9))));
})->throws(SignatureInvalid::class);

it('rejects a stored public key with an unsupported key type', function (): void {
    $cose = CborEncoder::map([
        [CborEncoder::uint(1), CborEncoder::uint(9)],       // kty: unknown
        [CborEncoder::uint(3), CborEncoder::nint(-7)],
    ]);

    crypto()->storedPublicKey(storedKey(base64_encode($cose)));
})->throws(UnsupportedAlgorithm::class);

it('rejects a stored public key with a missing label', function (): void {
    $cose = CborEncoder::map([
        [CborEncoder::uint(1), CborEncoder::uint(2)],       // kty only; no alg
    ]);

    crypto()->storedPublicKey(storedKey(base64_encode($cose)));
})->throws(MalformedCbor::class);

// --- verify ------------------------------------------------------------------

it('surfaces an unavailable algorithm as an unsupported-algorithm error', function (): void {
    // What an EdDSA credential does on a host without ext-sodium: it must fail
    // loudly, never degrade into "signature invalid" (which would look like a
    // wrong passkey to the user) and never into a silent pass.
    $key = new class implements PublicKey
    {
        public function algorithm(): Algorithm
        {
            return Algorithm::EdDSA;
        }

        public function verifier(): Verifier
        {
            return new class implements Verifier
            {
                public function algorithm(): Algorithm
                {
                    return Algorithm::EdDSA;
                }

                public function verify(string $message, string $signature): bool
                {
                    throw UnsupportedAlgorithmException::sodiumMissing();
                }
            };
        }
    };

    crypto()->verify($key, 'data', 'signature');
})->throws(UnsupportedAlgorithm::class);

it('treats a malformed signature as a failed verification, not an error', function (): void {
    $key = new class implements PublicKey
    {
        public function algorithm(): Algorithm
        {
            return Algorithm::RS256;
        }

        public function verifier(): Verifier
        {
            return new class implements Verifier
            {
                public function algorithm(): Algorithm
                {
                    return Algorithm::RS256;
                }

                public function verify(string $message, string $signature): bool
                {
                    throw InvalidSignatureException::make();
                }
            };
        }
    };

    expect(crypto()->verify($key, 'data', 'signature'))->toBeFalse();
});

// --- coseAlgorithm -----------------------------------------------------------

it('refuses a key whose algorithm has no COSE identifier', function (): void {
    $key = new class implements PublicKey
    {
        public function algorithm(): Algorithm
        {
            return Algorithm::HS256; // symmetric: never a WebAuthn credential
        }

        public function verifier(): Verifier
        {
            throw InvalidSignatureException::make();
        }
    };

    crypto()->coseAlgorithm($key);
})->throws(UnsupportedAlgorithm::class);

// --- messages in the app locale ----------------------------------------------

it('keeps crypto\'s untranslated detail out of the message, for logs only', function (Closure $fail, string $class, string $slovak): void {
    app()->setLocale('sk');

    $thrown = Thrown::by($fail);
    $previous = $thrown->getPrevious();

    expect($thrown)->toBeInstanceOf($class)
        ->and($thrown->getMessage())->toBe($slovak)
        ->and($previous)->toBeInstanceOf(CryptoException::class)
        ->and($thrown->context())->toBe(['reason' => $previous?->getMessage()]);
})->with([
    'malformed attestation CBOR' => [
        fn () => crypto()->attestationObject("\xff\xff\xff"),
        MalformedCbor::class,
        'Údaje CBOR majú neplatný formát.',
    ],
    'malformed stored key CBOR' => [
        fn () => crypto()->storedPublicKey(storedKey(base64_encode("\xff\xff\xff"))),
        MalformedCbor::class,
        'Údaje CBOR majú neplatný formát.',
    ],
    'stored key missing a label' => [
        fn () => crypto()->storedPublicKey(storedKey(base64_encode(CborEncoder::map([[CborEncoder::uint(1), CborEncoder::uint(2)]])))),
        MalformedCbor::class,
        'Údaje CBOR majú neplatný formát.',
    ],
    'truncated authenticator data' => [
        fn () => crypto()->authenticatorData('too short'),
        InvalidAuthenticatorData::class,
        'Údaje autentifikátora nie sú platné.',
    ],
    'malformed EC2 coordinate' => [
        fn () => crypto()->authenticatorData(attestedAuthData(CborEncoder::map([
            [CborEncoder::uint(1), CborEncoder::uint(2)],
            [CborEncoder::uint(3), CborEncoder::nint(-7)],
            [CborEncoder::nint(-1), CborEncoder::uint(1)],
            [CborEncoder::nint(-2), CborEncoder::bstr(str_repeat("\x01", 31))],
            [CborEncoder::nint(-3), CborEncoder::bstr(str_repeat("\x02", 32))],
        ]))),
        InvalidCoseKey::class,
        'Verejný kľúč COSE nie je platný.',
    ],
    'unknown COSE algorithm' => [
        fn () => crypto()->authenticatorData(attestedAuthData(CborEncoder::map([
            [CborEncoder::uint(1), CborEncoder::uint(2)],
            [CborEncoder::nint(-999), CborEncoder::uint(1)],
            [CborEncoder::uint(3), CborEncoder::nint(-999)],
        ]))),
        UnsupportedAlgorithm::class,
        'Algoritmus poverenia nie je podporovaný.',
    ],
    'stored key of an unknown type' => [
        fn () => crypto()->storedPublicKey(storedKey(base64_encode(CborEncoder::map([
            [CborEncoder::uint(1), CborEncoder::uint(9)],
            [CborEncoder::uint(3), CborEncoder::nint(-7)],
        ])))),
        UnsupportedAlgorithm::class,
        'Algoritmus poverenia nie je podporovaný.',
    ],
    'EdDSA without ext-sodium' => [
        fn () => crypto()->verify(new class implements PublicKey
        {
            public function algorithm(): Algorithm
            {
                return Algorithm::EdDSA;
            }

            public function verifier(): Verifier
            {
                return new class implements Verifier
                {
                    public function algorithm(): Algorithm
                    {
                        return Algorithm::EdDSA;
                    }

                    public function verify(string $message, string $signature): bool
                    {
                        throw UnsupportedAlgorithmException::sodiumMissing();
                    }
                };
            }
        }, 'data', 'signature'),
        UnsupportedAlgorithm::class,
        'Algoritmus poverenia nie je podporovaný.',
    ],
]);

it('keeps the name of a key algorithm without a COSE identifier for logs', function (): void {
    app()->setLocale('sk');

    $thrown = Thrown::by(fn () => crypto()->coseAlgorithm(new class implements PublicKey
    {
        public function algorithm(): Algorithm
        {
            return Algorithm::HS256;
        }

        public function verifier(): Verifier
        {
            throw InvalidSignatureException::make();
        }
    }));

    expect($thrown)->toBeInstanceOf(UnsupportedAlgorithm::class)
        ->and($thrown->getMessage())->toBe('Algoritmus poverenia nie je podporovaný.')
        ->and($thrown->context())->toBe(['reason' => 'HS256']);
});
