<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Crypto\Cose\CborDecoder;
use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Testing\TestCertificates;
use RoundlyConsulting\Crypto\Testing\TestLeafOptions;
use RoundlyConsulting\Passkeys\Attestation\PackedAttestationVerifier;
use RoundlyConsulting\Passkeys\Attestation\Statements\PackedStatement;
use RoundlyConsulting\Passkeys\Attestation\Support\CertificateExtensions;
use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\Enums\AttestationType;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAttestation;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAuthenticatorData;
use RoundlyConsulting\Passkeys\Support\CredentialCrypto;
use RoundlyConsulting\Passkeys\Testing\CborEncoder;
use RoundlyConsulting\Passkeys\Tests\Support\PackedVectors;
use RoundlyConsulting\Passkeys\Tests\Support\RawCertificate;
use RoundlyConsulting\Passkeys\Tests\Support\TestKeys;
use RoundlyConsulting\Passkeys\Tests\Support\Thrown;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

/**
 * Authenticator data carrying a real attested credential, so the verifier has a
 * credential key and an AAGUID to hold the statement against.
 *
 * @return array{0: AuthenticatorData, 1: string, 2: string} [parsed, raw authData, clientDataHash]
 */
function packedAuthData(WebAuthnVectors $vectors, string $aaguid): array
{
    $credentialId = $vectors->credentialId();

    $attested = $aaguid.pack('n', strlen($credentialId)).$credentialId.$vectors->coseKey();
    $raw = hash('sha256', WebAuthnVectors::RP_ID, true).chr(0x45).pack('N', 0).$attested;

    return [AuthenticatorData::parse($raw), $raw, hash('sha256', 'client-data', true)];
}

function packedVerifier(): PackedAttestationVerifier
{
    return new PackedAttestationVerifier(app(CredentialCrypto::class));
}

/**
 * @param  array<int|string, mixed>  $statement
 */
function verifyPacked(array $statement, string $authData, AuthenticatorData $parsed, string $clientDataHash): mixed
{
    return packedVerifier()->verify(
        new AttestationObject(format: 'packed', statement: $statement, authenticatorData: $authData),
        $parsed,
        $clientDataHash,
    );
}

/**
 * Decode a CBOR-shaped statement the way the ceremony does, so the fixtures are
 * exercised through the same bytes a browser would deliver.
 *
 * @return array<int|string, mixed>
 */
function decodeStatement(string $cbor): array
{
    $decoded = (new CborDecoder)->decode($cbor);

    expect($decoded)->toBeArray();

    /** @var array<int|string, mixed> $decoded */
    return $decoded;
}

beforeEach(function (): void {
    $this->aaguid = str_repeat("\x11", 16);
    $this->vectors = WebAuthnVectors::es256();

    [$this->parsed, $this->authData, $this->clientDataHash] = packedAuthData($this->vectors, $this->aaguid);
});

it('verifies a genuine x5c statement and reports basic', function (): void {
    $chain = PackedVectors::chain(aaguid: $this->aaguid);

    $statement = decodeStatement(
        (PackedVectors::chained($chain))($this->authData, $this->clientDataHash),
    );

    $result = verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash);

    expect($result->type)->toBe(AttestationType::Basic)
        ->and($result->format)->toBe('packed')
        ->and($result->trustPath)->not->toBeNull()
        ->and($result->trustPath?->leaf()->equals($chain->leaf()))->toBeTrue();
});

it('verifies a genuine self-attested statement', function (): void {
    $statement = decodeStatement(
        (PackedVectors::selfAttested($this->vectors))($this->authData, $this->clientDataHash),
    );

    $result = verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash);

    expect($result->type)->toBe(AttestationType::Self)
        ->and($result->trustPath)->toBeNull();
});

it('rejects x5c entries carried as base64 rather than raw DER', function (): void {
    // The §0 correction, pinned: Chain::fromX5c() decodes base64, which is right
    // for a JOSE x5c header and WRONG for CBOR. A verifier built on it would
    // reject every genuine authenticator; one that accepts base64 here would be
    // reading bytes no authenticator sends.
    $chain = PackedVectors::chain(aaguid: $this->aaguid);

    $statement = decodeStatement(
        (PackedVectors::chained($chain, x5c: PackedVectors::base64X5c($chain)))($this->authData, $this->clientDataHash),
    );

    verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class);

it('rejects a statement whose signature was tampered with', function (): void {
    $chain = PackedVectors::chain(aaguid: $this->aaguid);

    $statement = decodeStatement(
        (PackedVectors::chained($chain, tamperSignature: true))($this->authData, $this->clientDataHash),
    );

    verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class, 'could not be verified');

it('rejects a claimed algorithm the signing key never was', function (): void {
    $chain = PackedVectors::chain(aaguid: $this->aaguid, leafKeyType: 'RSA');

    // Claims ES256 while the batch certificate holds an RSA key.
    $statement = decodeStatement(
        (PackedVectors::chained($chain, algorithm: -7))($this->authData, $this->clientDataHash),
    );

    verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class, 'claims COSE algorithm -7');

it('rejects a self-attestation claiming an algorithm the credential key is not', function (): void {
    $statement = decodeStatement(
        (PackedVectors::selfAttested($this->vectors, algorithm: -257))($this->authData, $this->clientDataHash),
    );

    verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class, 'claims COSE algorithm -257');

it('rejects a batch certificate without the attestation subject OU', function (): void {
    $chain = PackedVectors::chain(aaguid: $this->aaguid, organizationalUnit: null);

    $statement = decodeStatement(
        (PackedVectors::chained($chain))($this->authData, $this->clientDataHash),
    );

    verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class, 'subject OU');

it('rejects a certified aaguid that disagrees with the authenticator data', function (): void {
    $chain = PackedVectors::chain(aaguid: str_repeat("\x22", 16));

    $statement = decodeStatement(
        (PackedVectors::chained($chain))($this->authData, $this->clientDataHash),
    );

    verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class, 'AAGUID');

it('rejects a critical id-fido-gen-ce-aaguid extension', function (): void {
    $chain = PackedVectors::chain(aaguid: $this->aaguid, criticalAaguid: true);

    $statement = decodeStatement(
        (PackedVectors::chained($chain))($this->authData, $this->clientDataHash),
    );

    verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class, 'must not be critical');

it('rejects an aaguid extension that is not an octet string', function (): void {
    $chain = TestCertificates::chain(
        length: 2,
        leafOptions: new TestLeafOptions(
            rawExtensions: [PackedVectors::AAGUID_OID => "\x02\x01\x05"], // INTEGER, not OCTET STRING
            subjectOrganizationalUnit: PackedVectors::ATTESTATION_OU,
        ),
    );

    $statement = decodeStatement(
        (PackedVectors::chained($chain))($this->authData, $this->clientDataHash),
    );

    verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class, 'OCTET STRING');

it('accepts a batch certificate carrying no aaguid extension at all', function (): void {
    $chain = PackedVectors::chain();

    $statement = decodeStatement(
        (PackedVectors::chained($chain))($this->authData, $this->clientDataHash),
    );

    $result = verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash);

    expect($result->type)->toBe(AttestationType::Basic);
});

it('rejects a chain longer than crypto will carry', function (): void {
    $chain = PackedVectors::chain(aaguid: $this->aaguid);
    $der = $chain->leaf()->der();

    $statement = decodeStatement(
        (PackedVectors::chained($chain, x5c: array_fill(0, 11, $der)))($this->authData, $this->clientDataHash),
    );

    verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class);

it('rejects a self-attested statement when no credential key was attested', function (): void {
    $bare = AuthenticatorData::parse(hash('sha256', WebAuthnVectors::RP_ID, true).chr(0x05).pack('N', 0));

    $statement = decodeStatement(
        (PackedVectors::selfAttested($this->vectors))($this->authData, $this->clientDataHash),
    );

    verifyPacked($statement, $this->authData, $bare, $this->clientDataHash);
})->throws(InvalidAuthenticatorData::class);

it('rejects a malformed statement', function (array $statement, string $message): void {
    verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->with([
    'ecdaa' => [['alg' => -7, 'sig' => 'x', 'ecdaaKeyId' => 'k'], 'ECDAA'],
    'no alg' => [['sig' => 'x'], 'alg must be'],
    'alg not an int' => [['alg' => 'ES256', 'sig' => 'x'], 'alg must be'],
    'no sig' => [['alg' => -7], 'sig must be'],
    'empty sig' => [['alg' => -7, 'sig' => ''], 'sig must be'],
    'x5c not an array' => [['alg' => -7, 'sig' => 'x', 'x5c' => 'cert'], 'x5c must be'],
    'x5c empty' => [['alg' => -7, 'sig' => 'x', 'x5c' => []], 'x5c must be'],
    'x5c entry not a string' => [['alg' => -7, 'sig' => 'x', 'x5c' => [42]], 'DER byte string'],
    'x5c entry not a certificate' => [['alg' => -7, 'sig' => 'x', 'x5c' => ['nonsense']], ''],
])->throws(InvalidAttestation::class);

it('types a statement straight off the wire', function (): void {
    $chain = PackedVectors::chain();

    $statement = PackedStatement::fromAttestationObject(new AttestationObject(
        format: 'packed',
        statement: decodeStatement(PackedVectors::statement(-7, 'sig', PackedVectors::x5c($chain))),
        authenticatorData: 'raw',
    ));

    expect($statement->algorithm)->toBe(-7)
        ->and($statement->signature)->toBe('sig')
        ->and($statement->x5c)->toHaveCount(2)
        ->and($statement->isSelfAttested())->toBeFalse();
});

it('reads basic constraints as RFC 5280 defines them', function (): void {
    $extensions = new CertificateExtensions;
    $chain = PackedVectors::chain();

    expect($extensions->isCertificateAuthority($chain->root()))->toBeTrue()
        ->and($extensions->isCertificateAuthority($chain->leaf()))->toBeFalse()
        ->and($extensions->fidoAaguid($chain->leaf()))->toBeNull()
        ->and($extensions->fidoAaguidIsCritical($chain->leaf()))->toBeFalse();
});

it('reads the fido aaguid extension it is handed', function (): void {
    $aaguid = str_repeat("\x33", 16);
    $chain = PackedVectors::chain(aaguid: $aaguid);

    expect((new CertificateExtensions)->fidoAaguid($chain->leaf()))->toBe($aaguid);
});

it('holds a batch certificate to WebAuthn §8.2.1', function (string $extensions, ?string $message): void {
    $certificate = RawCertificate::mint($extensions);

    $signature = $certificate->sign($this->authData.$this->clientDataHash);
    $statement = decodeStatement(PackedVectors::statement(-7, $signature, [$certificate->der]));

    if ($message === null) {
        $result = verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash);

        expect($result->type)->toBe(AttestationType::Basic);

        return;
    }

    expect(fn () => verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash))
        ->toThrow(InvalidAttestation::class, $message);
})->with([
    'CA:TRUE' => ["basicConstraints = critical,CA:TRUE\nkeyUsage = critical,digitalSignature", 'must not be a CA'],
    // basicConstraints whose bytes are not DER: unreadable is never "end entity".
    'unreadable basicConstraints' => ['2.5.29.19 = DER:0000', 'must not be a CA'],
    // Absent basicConstraints is RFC 5280's DEFAULT FALSE — an end entity.
    'no basicConstraints' => ['keyUsage = critical,digitalSignature', null],
]);

it('rejects a batch certificate whose OU is wrong even when everything else holds', function (): void {
    $certificate = RawCertificate::mint('basicConstraints = critical,CA:FALSE', organizationalUnit: 'Marketing');

    $signature = $certificate->sign($this->authData.$this->clientDataHash);
    $statement = decodeStatement(PackedVectors::statement(-7, $signature, [$certificate->der]));

    verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash);
})->throws(InvalidAttestation::class, 'subject OU');

it('encodes the packed statement fixtures as CBOR the decoder accepts', function (): void {
    $decoded = decodeStatement(PackedVectors::statement(-257, 'sig', []));

    expect($decoded)->toBe(['alg' => -257, 'sig' => 'sig'])
        ->and(CborEncoder::map([]))->toBe("\xa0");
});

// ── Messages in the app locale ───────────────────────────────────────────────

it('words why a packed statement is malformed in the app locale', function (array $statement, string $slovak, string $english): void {
    app()->setLocale('sk');

    $thrown = Thrown::by(fn () => verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash));

    expect($thrown)->toBeInstanceOf(InvalidAttestation::class)
        ->and($thrown->getMessage())->toBe("Atestačné vyhlásenie „packed“ je chybne zostavené: {$slovak}.")
        ->not->toContain($english);
})->with([
    'alg not an int' => [['alg' => 'ES256', 'sig' => 'x'], 'alg musí byť identifikátor algoritmu COSE', 'must be'],
    'empty sig' => [['alg' => -7, 'sig' => ''], 'sig musí byť neprázdny reťazec bajtov', 'must be'],
    'x5c empty' => [['alg' => -7, 'sig' => 'x', 'x5c' => []], 'x5c musí byť neprázdne pole certifikátov DER', 'must be'],
    'x5c entry not a string' => [['alg' => -7, 'sig' => 'x', 'x5c' => [42]], 'každá položka x5c musí byť reťazec bajtov DER', 'must be'],
]);

it('words an unreadable certificate in the app locale and keeps the parser\'s detail as the previous exception', function (): void {
    app()->setLocale('sk');

    $thrown = Thrown::by(fn () => verifyPacked(['alg' => -7, 'sig' => 'x', 'x5c' => ['nonsense']], $this->authData, $this->parsed, $this->clientDataHash));

    expect($thrown)->toBeInstanceOf(InvalidAttestation::class)
        ->and($thrown->getMessage())->toBe('Atestačné vyhlásenie „packed“ je chybne zostavené: niektorá položka x5c nie je čitateľný certifikát DER.')
        ->and($thrown->getPrevious())->toBeInstanceOf(CryptoException::class)
        ->and($thrown->getMessage())->not->toContain((string) $thrown->getPrevious()?->getMessage());
});

it('words a chain longer than crypto will carry in the app locale', function (): void {
    $chain = PackedVectors::chain(aaguid: $this->aaguid);
    $statement = decodeStatement(
        (PackedVectors::chained($chain, x5c: array_fill(0, 11, $chain->leaf()->der())))($this->authData, $this->clientDataHash),
    );

    app()->setLocale('sk');

    $thrown = Thrown::by(fn () => verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash));

    expect($thrown)->toBeInstanceOf(InvalidAttestation::class)
        ->and($thrown->getMessage())->toBe('Atestačné vyhlásenie „packed“ je chybne zostavené: x5c obsahuje viac certifikátov, než môže reťazec mať.')
        ->and($thrown->getPrevious())->toBeInstanceOf(CryptoException::class);
});

it('words a certificate key crypto refuses to load in the app locale', function (): void {
    $certificate = RawCertificate::mint('basicConstraints = critical,CA:FALSE', key: TestKeys::rsa(1024));
    $statement = decodeStatement(PackedVectors::statement(-257, 'signature', [$certificate->der]));

    app()->setLocale('sk');

    $thrown = Thrown::by(fn () => verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash));

    expect($thrown)->toBeInstanceOf(InvalidAttestation::class)
        ->and($thrown->getMessage())->toBe('Atestačné vyhlásenie „packed“ je chybne zostavené: verejný kľúč atestačného certifikátu sa nedá načítať.')
        ->and($thrown->getPrevious())->toBeInstanceOf(CryptoException::class);
});

it('words an aaguid extension that is not an octet string in the app locale', function (): void {
    $chain = TestCertificates::chain(
        length: 2,
        leafOptions: new TestLeafOptions(
            rawExtensions: [PackedVectors::AAGUID_OID => "\x02\x01\x05"], // INTEGER, not OCTET STRING
            subjectOrganizationalUnit: PackedVectors::ATTESTATION_OU,
        ),
    );
    $statement = decodeStatement((PackedVectors::chained($chain))($this->authData, $this->clientDataHash));

    app()->setLocale('sk');

    $thrown = Thrown::by(fn () => verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash));

    expect($thrown)->toBeInstanceOf(InvalidAttestation::class)
        ->and($thrown->getMessage())->toBe('Atestačné vyhlásenie „packed“ je chybne zostavené: rozšírenie id-fido-gen-ce-aaguid nie je OCTET STRING.')
        ->and($thrown->getPrevious())->toBeInstanceOf(CryptoException::class);
});

it('words a WebAuthn certificate requirement in the app locale', function (Closure $certificate, string $slovak, string $english): void {
    $statement = decodeStatement($certificate->call($this));

    app()->setLocale('sk');

    $thrown = Thrown::by(fn () => verifyPacked($statement, $this->authData, $this->parsed, $this->clientDataHash));

    expect($thrown)->toBeInstanceOf(InvalidAttestation::class)
        ->and($thrown->getMessage())->toBe("Atestačný certifikát „packed“ nespĺňa požiadavku WebAuthn: {$slovak}.")
        ->not->toContain($english);
})->with([
    'subject OU' => [
        fn (): string => (PackedVectors::chained(PackedVectors::chain(aaguid: $this->aaguid, organizationalUnit: null)))($this->authData, $this->clientDataHash),
        'OU v subjekte atestačného certifikátu musí byť „Authenticator Attestation“',
        'must be',
    ],
    'CA:TRUE' => [
        function (): string {
            $certificate = RawCertificate::mint("basicConstraints = critical,CA:TRUE\nkeyUsage = critical,digitalSignature");

            return PackedVectors::statement(-7, $certificate->sign($this->authData.$this->clientDataHash), [$certificate->der]);
        },
        'atestačný certifikát nesmie byť certifikačnou autoritou (basicConstraints CA:FALSE)',
        'must not be',
    ],
    'critical aaguid extension' => [
        fn (): string => (PackedVectors::chained(PackedVectors::chain(aaguid: $this->aaguid, criticalAaguid: true)))($this->authData, $this->clientDataHash),
        'rozšírenie id-fido-gen-ce-aaguid nesmie byť označené ako kritické',
        'must not be',
    ],
]);
