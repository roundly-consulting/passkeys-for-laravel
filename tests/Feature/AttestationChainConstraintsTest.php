<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Actions\GenerateRegistrationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\VerifyRegistrationAction;
use RoundlyConsulting\Passkeys\Attestation\AttestationAnchors;
use RoundlyConsulting\Passkeys\Attestation\AttestationVerifier;
use RoundlyConsulting\Passkeys\Attestation\AttestationVerifierRegistry;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Exceptions\AttestationUntrusted;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\PackedVectors;
use RoundlyConsulting\Passkeys\Tests\Support\Pki;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

/*
 * RFC 5280 §6.1.4 (k), (l), (m), (n): a certificate that signed another one in the
 * path must be a CA — basicConstraints CA:TRUE, keyCertSign when a keyUsage is
 * present — and every pathLenConstraint must hold. Linkage alone proves only that
 * a key signed; it says nothing about whether that key was ever allowed to.
 */

/**
 * @param  array<string, mixed>  $values
 */
function chainPolicy(array $values): void
{
    foreach ($values as $key => $value) {
        config()->set('passkeys.'.$key, $value);
    }

    foreach ([PasskeyConfig::class, AttestationVerifier::class, AttestationAnchors::class, AttestationVerifierRegistry::class] as $binding) {
        app()->forgetInstance($binding);
    }
}

function anchorAt(Pki $anchor): void
{
    chainPolicy([
        'attestation' => 'direct',
        'attestation_trust' => 'basic',
        'attestation_anchors' => ['defaults' => false, 'paths' => ['packed' => [$anchor->writePem()]]],
    ]);
}

/**
 * Enrol with a packed statement signed by $leaf, carrying x5c = [$leaf, ...$issuers].
 *
 * @param  list<Pki>  $issuers
 */
function enrolUnder(Pki $leaf, array $issuers): Passkey
{
    $user = User::query()->create(['name' => 'Mallory', 'email' => 'mallory@example.com']);
    $options = app(GenerateRegistrationOptionsAction::class)->execute($user);

    $x5c = [$leaf->der(), ...array_map(static fn (Pki $issuer): string => $issuer->der(), $issuers)];

    $payload = WebAuthnVectors::es256()->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
        'fmt' => 'packed',
        'attStmtFactory' => static fn (string $authData, string $clientDataHash): string => PackedVectors::statement(
            -7,
            $leaf->sign($authData.$clientDataHash),
            $x5c,
        ),
    ]);

    return app(VerifyRegistrationAction::class)->execute($user, RegistrationResponseData::fromArray($payload));
}

// ── The review's scenario ────────────────────────────────────────────────────

it('refuses a leaf minted under an end-entity certificate the anchored CA issued', function (): void {
    $root = Pki::root();
    $device = $root->issue('device-42.org.example', Pki::END_ENTITY);

    anchorAt($root);

    // An insider holding device-42's key mints an "attestation" leaf under it.
    enrolUnder($device->issueAttestationLeaf(), [$device]);
})->throws(AttestationUntrusted::class, '"CN=device-42.org.example, O=Passkeys Test, C=SK" signed a certificate in it but is not a certificate authority');

it('refuses the same forged chain under self, which waives anchoring but not chain validity', function (): void {
    $device = Pki::root()->issue('device-42.org.example', Pki::END_ENTITY);

    chainPolicy(['attestation' => 'direct', 'attestation_trust' => 'self']);

    enrolUnder($device->issueAttestationLeaf(), [$device]);
})->throws(AttestationUntrusted::class, 'is not a certificate authority');

it('refuses an issuer that is not a certificate authority', function (string $extensions): void {
    $root = Pki::root();
    $issuer = $root->issue('Batch Issuer', $extensions);

    anchorAt($root);

    enrolUnder($issuer->issueAttestationLeaf(), [$issuer]);
})->with([
    'CA:TRUE without keyCertSign' => [Pki::CA_WITHOUT_CERT_SIGN],
    'keyCertSign without basicConstraints' => [Pki::CERT_SIGN_WITHOUT_BASIC_CONSTRAINTS],
    'unreadable basicConstraints' => ["2.5.29.19 = DER:0000\nkeyUsage = critical,keyCertSign"],
    'unreadable keyUsage' => ["basicConstraints = critical,CA:TRUE\n2.5.29.15 = DER:0000"],
])->throws(AttestationUntrusted::class, 'is not a certificate authority');

it('refuses an anchor that is itself an end entity when it signs the chain', function (): void {
    $device = Pki::root()->issue('device-42.org.example', Pki::END_ENTITY);

    // The host (mistakenly) anchors an end-entity certificate; x5c omits it.
    anchorAt($device);

    enrolUnder($device->issueAttestationLeaf(), []);
})->throws(AttestationUntrusted::class, 'is not a certificate authority');

// ── pathLenConstraint ────────────────────────────────────────────────────────

it('refuses a chain longer than an intermediate\'s pathLenConstraint allows', function (): void {
    $root = Pki::root();
    $constrained = $root->issue('Constrained CA', Pki::CA_PATH_LENGTH_ZERO);
    $below = $constrained->issue('Sub CA', Pki::CA);

    anchorAt($root);

    enrolUnder($below->issueAttestationLeaf(), [$below, $constrained]);
})->throws(AttestationUntrusted::class, 'allows at most 0 intermediate certificate(s) below it');

it('refuses a chain longer than the anchor\'s own pathLenConstraint allows', function (): void {
    $root = Pki::root(Pki::CA_PATH_LENGTH_ZERO);
    $intermediate = $root->issue('Batch CA', Pki::CA);

    anchorAt($root);

    enrolUnder($intermediate->issueAttestationLeaf(), [$intermediate]);
})->throws(AttestationUntrusted::class, 'allows at most 0 intermediate certificate(s) below it');

// ── What stays accepted ──────────────────────────────────────────────────────

it('accepts a chain that honours every pathLenConstraint', function (): void {
    $root = Pki::root(Pki::CA_PATH_LENGTH_ZERO);

    anchorAt($root);

    expect(enrolUnder($root->issueAttestationLeaf(), [])->attestation_type)->toBe('basic');
});

it('accepts an intermediate whose pathLenConstraint of zero admits only the leaf', function (): void {
    $root = Pki::root();
    $intermediate = $root->issue('Batch CA', Pki::CA_PATH_LENGTH_ZERO);

    anchorAt($root);

    expect(enrolUnder($intermediate->issueAttestationLeaf(), [$intermediate])->attestation_type)->toBe('basic');
});

it('accepts a CA intermediate without a keyUsage extension, which restricts nothing', function (): void {
    $root = Pki::root();
    $intermediate = $root->issue('Batch CA', Pki::CA_WITHOUT_KEY_USAGE);

    anchorAt($root);

    expect(enrolUnder($intermediate->issueAttestationLeaf(), [$intermediate])->attestation_type)->toBe('basic');
});

it('accepts a chain that carries its anchored root in x5c', function (): void {
    $root = Pki::root();
    $intermediate = $root->issue('Batch CA', Pki::CA);

    anchorAt($root);

    expect(enrolUnder($intermediate->issueAttestationLeaf(), [$intermediate, $root])->attestation_type)->toBe('basic');
});
