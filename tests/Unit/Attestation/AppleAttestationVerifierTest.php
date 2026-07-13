<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Crypto\Cose\CborDecoder;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Testing\TestCertificateChain;
use RoundlyConsulting\Crypto\Testing\TestCertificates;
use RoundlyConsulting\Crypto\Testing\TestLeafOptions;
use RoundlyConsulting\Passkeys\Attestation\AppleAttestationVerifier;
use RoundlyConsulting\Passkeys\Attestation\Statements\AppleStatement;
use RoundlyConsulting\Passkeys\Attestation\Support\CertificateExtensions;
use RoundlyConsulting\Passkeys\Attestation\Support\KeysMatch;
use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\Enums\AttestationType;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAttestation;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAuthenticatorData;
use RoundlyConsulting\Passkeys\Tests\Support\AppleVectors;
use RoundlyConsulting\Passkeys\Tests\Support\RawCertificate;
use RoundlyConsulting\Passkeys\Tests\Support\TestKeys;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

/**
 * Authenticator data whose attested credential key is $key — Apple's credential
 * certificate certifies that very key, so the fixture has to register it.
 *
 * @return array{0: AuthenticatorData, 1: string, 2: string} [parsed, raw authData, clientDataHash]
 */
function appleAuthData(WebAuthnVectors $vectors): array
{
    $credentialId = $vectors->credentialId();

    // Apple platform authenticators send an all-zero AAGUID: anonymous, by design.
    $attested = str_repeat("\x00", 16).pack('n', strlen($credentialId)).$credentialId.$vectors->coseKey();
    $raw = hash('sha256', WebAuthnVectors::RP_ID, true).chr(0x45).pack('N', 0).$attested;

    return [AuthenticatorData::parse($raw), $raw, hash('sha256', 'client-data', true)];
}

/**
 * @return array<int|string, mixed>
 */
function decodeAppleStatement(string $cbor): array
{
    $decoded = (new CborDecoder)->decode($cbor);

    expect($decoded)->toBeArray();

    /** @var array<int|string, mixed> $decoded */
    return $decoded;
}

/**
 * @param  array<int|string, mixed>  $statement
 */
function verifyApple(array $statement, string $authData, AuthenticatorData $parsed, string $clientDataHash): mixed
{
    return (new AppleAttestationVerifier)->verify(
        new AttestationObject(format: 'apple', statement: $statement, authenticatorData: $authData),
        $parsed,
        $clientDataHash,
    );
}

/** The genuine Apple chain for this ceremony: credCert (nonce + credential key) → intermediate → root. */
function appleChain(EcKey $credentialKey, string $authData, string $clientDataHash, bool $withNonce = true): TestCertificateChain
{
    return AppleVectors::chain(
        nonce: hash('sha256', $authData.$clientDataHash, true),
        credentialKey: $credentialKey,
        withNonce: $withNonce,
    );
}

beforeEach(function (): void {
    $this->credentialKey = EcKey::generate();
    $this->vectors = WebAuthnVectors::es256FromKey($this->credentialKey->key);

    [$this->parsed, $this->authData, $this->clientDataHash] = appleAuthData($this->vectors);
});

it('verifies a genuine apple statement and reports anonca', function (): void {
    $chain = appleChain($this->credentialKey, $this->authData, $this->clientDataHash);

    // Apple omits the root — the statement carries [credCert, intermediate].
    $statement = decodeAppleStatement(AppleVectors::attStmt(AppleVectors::x5c($chain)));

    $result = verifyApple($statement, $this->authData, $this->parsed, $this->clientDataHash);

    // AnonCA, never Basic: Apple's attestation reveals nothing about the device.
    expect($result->type)->toBe(AttestationType::AnonCa)
        ->and($result->format)->toBe('apple')
        ->and($result->trustPath)->not->toBeNull()
        ->and($result->trustPath?->count())->toBe(2)
        ->and($result->trustPath?->leaf()->equals($chain->leaf()))->toBeTrue();
});

it('verifies a statement that carries the root as well', function (): void {
    $chain = appleChain($this->credentialKey, $this->authData, $this->clientDataHash);

    $statement = decodeAppleStatement(AppleVectors::attStmt(AppleVectors::x5c($chain, omitRoot: false)));

    $result = verifyApple($statement, $this->authData, $this->parsed, $this->clientDataHash);

    expect($result->trustPath?->count())->toBe(3);
});

// ── The nonce: the whole security property of this format ────────────────────

it('rejects a nonce that is not this ceremony\'s hash', function (): void {
    $chain = AppleVectors::chain(nonce: random_bytes(32), credentialKey: $this->credentialKey);

    $statement = decodeAppleStatement(AppleVectors::attStmt(AppleVectors::x5c($chain)));

    verifyApple($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class, 'nonce');

it('rejects a genuine statement replayed from another ceremony', function (): void {
    // A real, correctly-formed Apple statement — minted over ANOTHER ceremony's
    // bytes. Without the nonce check this would enrol; that is the replay.
    $other = WebAuthnVectors::es256FromKey($this->credentialKey->key);
    [, $otherAuthData, $otherClientDataHash] = appleAuthData($other);

    $chain = appleChain($this->credentialKey, $otherAuthData, $otherClientDataHash);

    $statement = decodeAppleStatement(AppleVectors::attStmt(AppleVectors::x5c($chain)));

    verifyApple($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class, 'nonce');

it('rejects a statement whose authenticator data was tampered with', function (): void {
    $chain = appleChain($this->credentialKey, $this->authData, $this->clientDataHash);

    $statement = decodeAppleStatement(AppleVectors::attStmt(AppleVectors::x5c($chain)));

    // Flip the sign counter: the certified nonce no longer hashes these bytes.
    $tampered = $this->authData;
    $tampered[33] = "\x09";

    verifyApple($statement, $tampered, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class, 'nonce');

it('rejects a statement whose client data hash was tampered with', function (): void {
    $chain = appleChain($this->credentialKey, $this->authData, $this->clientDataHash);

    $statement = decodeAppleStatement(AppleVectors::attStmt(AppleVectors::x5c($chain)));

    verifyApple($statement, $this->authData, $this->parsed, hash('sha256', 'other-client-data', true));
})->throws(InvalidAttestation::class, 'nonce');

it('rejects a credential certificate carrying no nonce extension', function (): void {
    $chain = appleChain($this->credentialKey, $this->authData, $this->clientDataHash, withNonce: false);

    $statement = decodeAppleStatement(AppleVectors::attStmt(AppleVectors::x5c($chain)));

    verifyApple($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class, '1.2.840.113635.100.8.2');

it('rejects a nonce extension of the wrong DER shape', function (string $der): void {
    $chain = TestCertificates::chain(
        length: 2,
        leafOptions: new TestLeafOptions(rawExtensions: [AppleVectors::NONCE_OID => $der]),
        leafKey: $this->credentialKey,
    );

    $statement = decodeAppleStatement(AppleVectors::attStmt(AppleVectors::x5c($chain)));

    verifyApple($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->with([
    // An INTEGER where the SEQUENCE should be.
    'not a sequence' => ["\x02\x01\x05"],
    // SEQUENCE { OCTET STRING } — the octets are there, but not under [1].
    'no [1] element' => ["\x30\x04\x04\x02\xde\xad"],
    // SEQUENCE { [1] {} } — an empty container.
    'empty [1] element' => ["\x30\x02\xa1\x00"],
    // SEQUENCE { [1] { INTEGER } } — [1] holds something that is not the nonce.
    'not an octet string' => ["\x30\x05\xa1\x03\x02\x01\x05"],
])->throws(InvalidAttestation::class);

// ── The key binding ──────────────────────────────────────────────────────────

it('rejects a certificate that certifies a different key than the credential', function (): void {
    // The nonce is right, the chain is genuine — but the certificate is over
    // somebody else's key, so it says nothing about THIS credential.
    $foreign = EcKey::generate();

    $chain = AppleVectors::chain(
        nonce: hash('sha256', $this->authData.$this->clientDataHash, true),
        credentialKey: $foreign,
    );

    $statement = decodeAppleStatement(AppleVectors::attStmt(AppleVectors::x5c($chain)));

    verifyApple($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class, 'different public key');

it('rejects a credential certificate whose key crypto refuses to load', function (): void {
    // The nonce is right — but the certificate certifies an undersized RSA key,
    // which crypto will not load. A key we cannot read is never a key we match.
    $nonce = hash('sha256', $this->authData.$this->clientDataHash, true);

    $certificate = RawCertificate::mint(
        "basicConstraints = critical,CA:FALSE\n".AppleVectors::NONCE_OID.' = DER:'.bin2hex(AppleVectors::nonceExtension($nonce)),
        key: TestKeys::rsa(1024),
    );

    $statement = decodeAppleStatement(AppleVectors::attStmt([$certificate->der]));

    verifyApple($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class);

it('rejects a statement when no credential key was attested at all', function (): void {
    $bare = AuthenticatorData::parse(hash('sha256', WebAuthnVectors::RP_ID, true).chr(0x05).pack('N', 0));

    $chain = appleChain($this->credentialKey, $this->authData, $this->clientDataHash);
    $statement = decodeAppleStatement(AppleVectors::attStmt(AppleVectors::x5c($chain)));

    verifyApple($statement, $this->authData, $bare, $this->clientDataHash);
})->throws(InvalidAuthenticatorData::class);

// ── The statement's shape ────────────────────────────────────────────────────

it('rejects x5c entries carried as base64 rather than raw DER', function (): void {
    // CBOR carries the certificate bytes themselves; the base64 x5c helper is the
    // JOSE shape and would reject every genuine authenticator.
    $chain = appleChain($this->credentialKey, $this->authData, $this->clientDataHash);

    $statement = decodeAppleStatement(AppleVectors::attStmt([$chain->leaf()->base64()]));

    verifyApple($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class);

it('rejects a malformed statement', function (array $statement): void {
    verifyApple($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->with([
    'no x5c' => [[]],
    'x5c not an array' => [['x5c' => 'cert']],
    'x5c empty' => [['x5c' => []]],
    'x5c entry not a string' => [['x5c' => [42]]],
    'x5c entry empty' => [['x5c' => ['']]],
    'x5c entry not a certificate' => [['x5c' => ['nonsense']]],
])->throws(InvalidAttestation::class);

it('types a statement straight off the wire', function (): void {
    $chain = appleChain($this->credentialKey, $this->authData, $this->clientDataHash);

    $statement = AppleStatement::fromAttestationObject(new AttestationObject(
        format: 'apple',
        statement: decodeAppleStatement(AppleVectors::attStmt(AppleVectors::x5c($chain))),
        authenticatorData: $this->authData,
    ));

    expect($statement->x5c)->toHaveCount(2)
        ->and($statement->x5c[0])->toBe($chain->leaf()->der());
});

// ── The extension reader ─────────────────────────────────────────────────────

it('reads the apple nonce extension it is handed', function (): void {
    $nonce = hash('sha256', $this->authData.$this->clientDataHash, true);
    $chain = appleChain($this->credentialKey, $this->authData, $this->clientDataHash);

    $extensions = new CertificateExtensions;

    expect($extensions->appleNonce($chain->leaf()))->toBe($nonce)
        ->and($extensions->appleNonce($chain->root()))->toBeNull()
        ->and(CertificateExtensions::APPLE_NONCE_OID)->toBe('1.2.840.113635.100.8.2');
});

// ── Key equality ─────────────────────────────────────────────────────────────

it('compares public keys on their material', function (): void {
    $ec = EcKey::generate();
    $rsa = RsaKey::generate();
    $okp = OkpKey::generate();

    expect(KeysMatch::check($ec, EcKey::public($ec->publicPem())))->toBeTrue()
        ->and(KeysMatch::check($ec, EcKey::generate()))->toBeFalse()
        ->and(KeysMatch::check($ec, EcKey::generate('P-384')))->toBeFalse()
        ->and(KeysMatch::check($rsa, RsaKey::public($rsa->publicPem())))->toBeTrue()
        ->and(KeysMatch::check($rsa, RsaKey::generate()))->toBeFalse()
        ->and(KeysMatch::check($okp, OkpKey::ed25519($okp->publicKey)))->toBeTrue()
        ->and(KeysMatch::check($okp, OkpKey::generate()))->toBeFalse()
        // Different key TYPES are never the same key.
        ->and(KeysMatch::check($ec, $rsa))->toBeFalse()
        ->and(KeysMatch::check($okp, $ec))->toBeFalse();
});
