<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Crypto\Testing\TestCertificateChain;
use RoundlyConsulting\Passkeys\Actions\GenerateRegistrationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\VerifyRegistrationAction;
use RoundlyConsulting\Passkeys\Attestation\AttestationAnchors;
use RoundlyConsulting\Passkeys\Attestation\AttestationVerifier;
use RoundlyConsulting\Passkeys\Attestation\AttestationVerifierRegistry;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Exceptions\AttestationRequired;
use RoundlyConsulting\Passkeys\Exceptions\AttestationUntrusted;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAttestation;
use RoundlyConsulting\Passkeys\Exceptions\UnsupportedAttestationFormat;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\PackedVectors;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

/*
 * The §7 trust ladder, end to end through the real ceremony:
 *
 *   Ignore ⊂ SelfAttested (maths) ⊂ Basic (maths + anchor)
 */

/**
 * @param  array<string, mixed>  $values
 */
function trust(array $values): void
{
    foreach ($values as $key => $value) {
        config()->set('passkeys.'.$key, $value);
    }

    // The typed config and everything downstream of it are singletons.
    foreach ([PasskeyConfig::class, AttestationVerifier::class, AttestationAnchors::class, AttestationVerifierRegistry::class] as $binding) {
        app()->forgetInstance($binding);
    }
}

/**
 * @param  array<string, mixed>  $overrides
 */
function enrol(User $user, WebAuthnVectors $vectors, array $overrides = []): Passkey
{
    $options = app(GenerateRegistrationOptionsAction::class)->execute($user);

    $payload = $vectors->registrationResponse(array_merge([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ], $overrides));

    return app(VerifyRegistrationAction::class)->execute($user, RegistrationResponseData::fromArray($payload));
}

/** Write a chain's root out as the host's configured trust anchor for a format. */
function anchor(TestCertificateChain $chain, string $format = 'packed'): string
{
    $path = (string) tempnam(sys_get_temp_dir(), 'passkeys-anchor-').'.pem';

    file_put_contents($path, $chain->root()->pem());

    trust(['attestation_anchors' => ['defaults' => false, 'paths' => [$format => [$path]]]]);

    return $path;
}

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Ada', 'email' => 'ada@example.com']);
    $this->aaguid = str_repeat("\x11", 16);
    $this->chain = PackedVectors::chain(aaguid: $this->aaguid);
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

// ── Ignore ───────────────────────────────────────────────────────────────────

it('records a broken packed statement under ignore without reading it', function (): void {
    $passkey = enrol($this->user, WebAuthnVectors::es256(), [
        'fmt' => 'packed',
        'attStmt' => PackedVectors::statement(-7, 'garbage', ['also-garbage']),
    ]);

    expect($passkey->attestation_format)->toBe('packed')
        ->and($passkey->attestation_type)->toBe('none');
});

it('rejects an unverifiable known format under ignore with reject_unknown_fmt', function (): void {
    trust(['reject_unknown_fmt' => true]);

    enrol($this->user, WebAuthnVectors::es256(), [
        'fmt' => 'packed',
        'attStmt' => PackedVectors::statement(-7, 'garbage', ['also-garbage']),
    ]);
})->throws(InvalidAttestation::class);

it('rejects an unknown format under ignore with reject_unknown_fmt', function (): void {
    trust(['reject_unknown_fmt' => true]);

    enrol($this->user, WebAuthnVectors::es256(), ['fmt' => 'android-safetynet']);
})->throws(UnsupportedAttestationFormat::class, 'none, packed');

it('accepts a genuine packed statement under ignore with reject_unknown_fmt, anchors unconsulted', function (): void {
    trust(['reject_unknown_fmt' => true, 'attestation_anchors' => ['defaults' => false, 'paths' => []]]);

    $vectors = WebAuthnVectors::es256();

    $passkey = enrol($this->user, $vectors, [
        'fmt' => 'packed',
        'aaguid' => $this->aaguid,
        'attStmtFactory' => PackedVectors::chained($this->chain),
    ]);

    expect($passkey->attestation_type)->toBe('basic');
});

// ── SelfAttested ─────────────────────────────────────────────────────────────

it('accepts self-attestation under self', function (): void {
    trust(['attestation' => 'direct', 'attestation_trust' => 'self']);

    $vectors = WebAuthnVectors::es256();

    $passkey = enrol($this->user, $vectors, [
        'fmt' => 'packed',
        'attStmtFactory' => PackedVectors::selfAttested($vectors),
    ]);

    expect($passkey->attestation_type)->toBe('self');
});

it('accepts self-attestation under self for every supported credential algorithm', function (string $algorithm): void {
    trust([
        'attestation' => 'direct',
        'attestation_trust' => 'self',
        'algorithms' => [-7, -257, -8],
    ]);

    $vectors = match ($algorithm) {
        'rs256' => WebAuthnVectors::rs256(),
        'eddsa' => WebAuthnVectors::eddsa(),
        default => WebAuthnVectors::es256(),
    };

    $passkey = enrol($this->user, $vectors, [
        'fmt' => 'packed',
        'attStmtFactory' => PackedVectors::selfAttested($vectors),
    ]);

    expect($passkey->attestation_type)->toBe('self');
})->with(['es256', 'rs256', 'eddsa']);

it('accepts an un-anchored but sound chain under self', function (): void {
    trust([
        'attestation' => 'direct',
        'attestation_trust' => 'self',
        'attestation_anchors' => ['defaults' => false, 'paths' => []],
    ]);

    $passkey = enrol($this->user, WebAuthnVectors::es256(), [
        'fmt' => 'packed',
        'aaguid' => $this->aaguid,
        'attStmtFactory' => PackedVectors::chained($this->chain),
    ]);

    expect($passkey->attestation_type)->toBe('basic');
});

it('refuses a none statement under self', function (): void {
    trust(['attestation' => 'direct', 'attestation_trust' => 'self']);

    enrol($this->user, WebAuthnVectors::es256(), ['fmt' => 'none']);
})->throws(AttestationRequired::class);

it('refuses a tampered self-attestation under self', function (): void {
    trust(['attestation' => 'direct', 'attestation_trust' => 'self']);

    $vectors = WebAuthnVectors::es256();

    enrol($this->user, $vectors, [
        'fmt' => 'packed',
        'attStmtFactory' => PackedVectors::selfAttested($vectors, tamperSignature: true),
    ]);
})->throws(InvalidAttestation::class);

it('refuses a self-attestation signed by the wrong key under self', function (): void {
    trust(['attestation' => 'direct', 'attestation_trust' => 'self']);

    $vectors = WebAuthnVectors::es256();
    $other = WebAuthnVectors::es256();

    enrol($this->user, $vectors, [
        'fmt' => 'packed',
        'attStmtFactory' => PackedVectors::selfAttested($other),
    ]);
})->throws(InvalidAttestation::class);

// ── Basic ────────────────────────────────────────────────────────────────────

it('accepts a chain anchored by equality under basic', function (): void {
    trust(['attestation' => 'direct', 'attestation_trust' => 'basic']);
    anchor($this->chain);

    $passkey = enrol($this->user, WebAuthnVectors::es256(), [
        'fmt' => 'packed',
        'aaguid' => $this->aaguid,
        'attStmtFactory' => PackedVectors::chained($this->chain),
    ]);

    expect($passkey->attestation_format)->toBe('packed')
        ->and($passkey->attestation_type)->toBe('basic');
});

it('accepts a chain anchored by completion when x5c omits the root', function (): void {
    trust(['attestation' => 'direct', 'attestation_trust' => 'basic']);
    anchor($this->chain);

    $leafOnly = [$this->chain->leaf()->der()];

    $passkey = enrol($this->user, WebAuthnVectors::es256(), [
        'fmt' => 'packed',
        'aaguid' => $this->aaguid,
        'attStmtFactory' => PackedVectors::chained($this->chain, x5c: $leafOnly),
    ]);

    expect($passkey->attestation_type)->toBe('basic');
});

it('accepts an RSA batch certificate under basic', function (): void {
    $chain = PackedVectors::chain(leafKeyType: 'RSA');

    trust(['attestation' => 'direct', 'attestation_trust' => 'basic']);
    anchor($chain);

    $passkey = enrol($this->user, WebAuthnVectors::es256(), [
        'fmt' => 'packed',
        'attStmtFactory' => PackedVectors::chained($chain),
    ]);

    expect($passkey->attestation_type)->toBe('basic');
});

it('refuses self-attestation under basic', function (): void {
    trust(['attestation' => 'direct', 'attestation_trust' => 'basic']);
    anchor($this->chain);

    $vectors = WebAuthnVectors::es256();

    enrol($this->user, $vectors, [
        'fmt' => 'packed',
        'attStmtFactory' => PackedVectors::selfAttested($vectors),
    ]);
})->throws(AttestationUntrusted::class, 'does not accept self-attestation');

it('refuses a chain whose root is not anchored, naming the root', function (): void {
    $rogue = PackedVectors::chain();

    trust(['attestation' => 'direct', 'attestation_trust' => 'basic']);
    anchor($this->chain);

    enrol($this->user, WebAuthnVectors::es256(), [
        'fmt' => 'packed',
        'attStmtFactory' => PackedVectors::chained($rogue),
    ]);
})->throws(AttestationUntrusted::class, 'Crypto Test Root CA');

it('refuses basic when no anchor is configured for the format, naming the key', function (): void {
    trust([
        'attestation' => 'direct',
        'attestation_trust' => 'basic',
        'attestation_anchors' => ['defaults' => false, 'paths' => []],
    ]);

    enrol($this->user, WebAuthnVectors::es256(), [
        'fmt' => 'packed',
        'attStmtFactory' => PackedVectors::chained($this->chain),
    ]);
})->throws(AttestationUntrusted::class, 'passkeys.attestation_anchors.paths.packed');

it('refuses a none statement under basic', function (): void {
    trust(['attestation' => 'direct', 'attestation_trust' => 'basic']);

    enrol($this->user, WebAuthnVectors::es256(), ['fmt' => 'none']);
})->throws(AttestationRequired::class);

it('refuses a chain whose certificates do not link', function (): void {
    trust(['attestation' => 'direct', 'attestation_trust' => 'self']);

    $other = PackedVectors::chain();

    // leaf from one authority, "issuer" from another: ordered, but not linked.
    $unlinked = [$this->chain->leaf()->der(), $other->root()->der()];

    enrol($this->user, WebAuthnVectors::es256(), [
        'fmt' => 'packed',
        'aaguid' => $this->aaguid,
        'attStmtFactory' => PackedVectors::chained($this->chain, x5c: $unlinked),
    ]);
})->throws(AttestationUntrusted::class, 'not linked');

// ── Validity dates (D-E) ─────────────────────────────────────────────────────

it('refuses an attestation certificate that has expired, and says so', function (): void {
    trust(['attestation' => 'direct', 'attestation_trust' => 'basic']);
    anchor($this->chain);

    $statement = PackedVectors::chained($this->chain);

    CarbonImmutable::setTestNow($this->chain->leaf()->notAfter()->addDay());

    enrol($this->user, WebAuthnVectors::es256(), [
        'fmt' => 'packed',
        'attStmtFactory' => $statement,
    ]);
})->throws(AttestationUntrusted::class, 'expired');

it('refuses an attestation certificate that is not yet valid', function (): void {
    trust(['attestation' => 'direct', 'attestation_trust' => 'basic']);
    anchor($this->chain);

    $statement = PackedVectors::chained($this->chain);

    CarbonImmutable::setTestNow($this->chain->leaf()->notBefore()->subDay());

    enrol($this->user, WebAuthnVectors::es256(), [
        'fmt' => 'packed',
        'attStmtFactory' => $statement,
    ]);
})->throws(AttestationUntrusted::class, 'not valid until');

it('forgives a lapse inside the configured clock skew', function (): void {
    trust([
        'attestation' => 'direct',
        'attestation_trust' => 'basic',
        'attestation_clock_skew' => 3600,
    ]);
    anchor($this->chain);

    $statement = PackedVectors::chained($this->chain);

    CarbonImmutable::setTestNow($this->chain->leaf()->notAfter()->addMinutes(30));

    $passkey = enrol($this->user, WebAuthnVectors::es256(), [
        'fmt' => 'packed',
        'attStmtFactory' => $statement,
    ]);

    expect($passkey->attestation_type)->toBe('basic');
});

it('enforces validity dates under self too, where anchoring is waived', function (): void {
    trust([
        'attestation' => 'direct',
        'attestation_trust' => 'self',
        'attestation_anchors' => ['defaults' => false, 'paths' => []],
    ]);

    $statement = PackedVectors::chained($this->chain);

    CarbonImmutable::setTestNow($this->chain->leaf()->notAfter()->addDay());

    enrol($this->user, WebAuthnVectors::es256(), [
        'fmt' => 'packed',
        'attStmtFactory' => $statement,
    ]);
})->throws(AttestationUntrusted::class, 'expired');

// ── AAGUID allow-list (D-C) ──────────────────────────────────────────────────

it('accepts an allow-listed aaguid', function (): void {
    trust([
        'attestation' => 'direct',
        'attestation_trust' => 'basic',
        'aaguids' => ['allowed' => ['11111111-1111-1111-1111-111111111111']],
    ]);
    anchor($this->chain);

    $passkey = enrol($this->user, WebAuthnVectors::es256(), [
        'fmt' => 'packed',
        'aaguid' => $this->aaguid,
        'attStmtFactory' => PackedVectors::chained($this->chain),
    ]);

    expect($passkey->aaguid)->toBe('11111111-1111-1111-1111-111111111111');
});

it('refuses an aaguid outside the allow-list, naming it', function (): void {
    trust([
        'attestation' => 'direct',
        'attestation_trust' => 'basic',
        'aaguids' => ['allowed' => ['22222222-2222-2222-2222-222222222222']],
    ]);
    anchor($this->chain);

    enrol($this->user, WebAuthnVectors::es256(), [
        'fmt' => 'packed',
        'aaguid' => $this->aaguid,
        'attStmtFactory' => PackedVectors::chained($this->chain),
    ]);
})->throws(AttestationUntrusted::class, '11111111-1111-1111-1111-111111111111');

it('refuses an authenticator that sends no aaguid when a list is configured', function (): void {
    trust([
        'attestation' => 'direct',
        'attestation_trust' => 'self',
        'aaguids' => ['allowed' => ['22222222-2222-2222-2222-222222222222']],
    ]);

    $vectors = WebAuthnVectors::es256();

    enrol($this->user, $vectors, [
        'fmt' => 'packed',
        'aaguid' => str_repeat("\x00", 16),
        'attStmtFactory' => PackedVectors::selfAttested($vectors),
    ]);
})->throws(AttestationUntrusted::class, '(none)');
