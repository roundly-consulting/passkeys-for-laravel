<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\X509\Chain;
use RoundlyConsulting\Passkeys\Attestation\AttestationAnchors;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\Exceptions\InvalidConfiguration;
use RoundlyConsulting\Passkeys\Tests\Support\PackedVectors;

/**
 * The shipped Google hardware-attestation roots, fetched from Google's own
 * published list at
 * https://developer.android.com/privacy-and-security/security-key-attestation
 * and pinned here so a swapped, stale or forged PEM cannot slip into the trust
 * store unnoticed. Nothing is trusted whose fingerprint is not asserted.
 *
 * @var array<string, string>
 */
const SHIPPED_ANDROID_ROOTS = [
    'google-hardware-attestation-2016.pem' => 'c1984a3ef45c1e2a918551de10603c86f7051b2249c4891cae3230eabd0c97d5',
    'google-hardware-attestation-2019.pem' => '1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc',
    'google-hardware-attestation-2021.pem' => 'ab6641178a36e179aa0c1cdddf9a16eb45fa20943e2b8cd7c7c05c26cf8b487a',
    'google-hardware-attestation-2022.pem' => 'cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc',
    'google-key-attestation-ca1-2025.pem' => '6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0',
];

/**
 * The shipped Apple WebAuthn Root CA, fetched from Apple's own published list at
 * https://www.apple.com/certificateauthority/private/ (the PEM at
 * https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem) and
 * pinned here. It is NOT Apple's App Attest root, nor an App Store root: a wrong
 * anchor would accept forged attestations and look like it worked.
 *
 * @var array<string, string>
 */
const SHIPPED_APPLE_ROOTS = [
    'apple-webauthn-root-ca.pem' => '0915dd5c07a28db549d1f677bb5a75d4bfbe9561a773424327762e9e02f9bb29',
];

/**
 * @param  array<string, mixed>  $overrides
 */
function anchorsFor(array $overrides = []): AttestationAnchors
{
    return new AttestationAnchors(PasskeyConfig::fromArray(array_merge([
        'rp' => ['id' => 'example.com'],
        'origins' => ['https://example.com'],
    ], $overrides)));
}

function writeAnchor(string $contents): string
{
    $path = (string) tempnam(sys_get_temp_dir(), 'passkeys-anchors-').'.pem';

    file_put_contents($path, $contents);

    return $path;
}

it('ships the google hardware attestation roots, byte for byte', function (): void {
    $anchors = anchorsFor()->for('android-key');

    $fingerprints = array_map(
        static fn ($certificate): string => $certificate->fingerprint(HashAlgorithm::Sha256),
        $anchors,
    );

    expect($anchors)->toHaveCount(count(SHIPPED_ANDROID_ROOTS));

    foreach (SHIPPED_ANDROID_ROOTS as $file => $fingerprint) {
        expect($fingerprints)->toContain($fingerprint);
        expect(SHIPPED_ANDROID_ROOTS[$file])->toBe($fingerprint);
    }
});

it('ships the apple webauthn root ca, byte for byte', function (): void {
    $anchors = anchorsFor()->for('apple');

    expect($anchors)->toHaveCount(count(SHIPPED_APPLE_ROOTS));

    $root = $anchors[0];

    expect($root->fingerprint(HashAlgorithm::Sha256))->toBe(SHIPPED_APPLE_ROOTS['apple-webauthn-root-ca.pem'])
        ->and($root->commonName())->toBe('Apple WebAuthn Root CA')
        ->and($root->isSelfSigned())->toBeTrue();
});

it('drops the shipped roots when defaults are switched off', function (): void {
    $anchors = anchorsFor(['attestation_anchors' => ['defaults' => false]]);

    expect($anchors->for('android-key'))->toBe([])
        ->and($anchors->for('apple'))->toBe([]);
});

it('ships no default anchor for vendor-specific formats', function (): void {
    expect(anchorsFor()->for('packed'))->toBe([])
        ->and(anchorsFor()->for('tpm'))->toBe([]);
});

it('never lets a format name off the wire walk the filesystem', function (): void {
    expect(anchorsFor()->for('../../../etc'))->toBe([]);
});

it('loads a host-configured PEM bundle as independent anchors', function (): void {
    $one = PackedVectors::chain();
    $two = PackedVectors::chain();

    $path = writeAnchor($one->root()->pem()."\n".$two->root()->pem());

    $anchors = anchorsFor([
        'attestation_anchors' => ['defaults' => false, 'paths' => ['packed' => [$path]]],
    ]);

    expect($anchors->for('packed'))->toHaveCount(2);
});

it('anchors a chain by equality and by completion', function (): void {
    $chain = PackedVectors::chain();
    $path = writeAnchor($chain->root()->pem());

    $anchors = anchorsFor([
        'attestation_anchors' => ['defaults' => false, 'paths' => ['packed' => [$path]]],
    ]);

    $withRoot = $chain->chain;
    $withoutRoot = new Chain([$chain->leaf()]);

    expect($anchors->anchorFor($withRoot, 'packed')?->equals($chain->root()))->toBeTrue()
        ->and($anchors->anchorFor($withoutRoot, 'packed')?->equals($chain->root()))->toBeTrue();
});

it('anchors nothing when the chain reaches a different root', function (): void {
    $mine = PackedVectors::chain();
    $theirs = PackedVectors::chain();

    $anchors = anchorsFor([
        'attestation_anchors' => ['defaults' => false, 'paths' => ['packed' => [writeAnchor($mine->root()->pem())]]],
    ]);

    expect($anchors->anchorFor($theirs->chain, 'packed'))->toBeNull();
});

it('memoizes a format\'s anchors', function (): void {
    $anchors = anchorsFor();

    expect($anchors->for('android-key'))->toBe($anchors->for('android-key'));
});

it('fails loudly on an anchor path that cannot be read', function (): void {
    anchorsFor([
        'attestation_anchors' => ['defaults' => false, 'paths' => ['packed' => ['/does/not/exist.pem']]],
    ])->for('packed');
})->throws(InvalidConfiguration::class, 'passkeys.attestation_anchors.paths.packed');

it('fails loudly on an anchor file with no certificate in it', function (): void {
    anchorsFor([
        'attestation_anchors' => ['defaults' => false, 'paths' => ['packed' => [writeAnchor('not a certificate')]]],
    ])->for('packed');
})->throws(InvalidConfiguration::class);

it('fails loudly on a PEM block that is not a certificate', function (): void {
    $rubbish = "-----BEGIN CERTIFICATE-----\nZm9vYmFy\n-----END CERTIFICATE-----\n";

    anchorsFor([
        'attestation_anchors' => ['defaults' => false, 'paths' => ['packed' => [writeAnchor($rubbish)]]],
    ])->for('packed');
})->throws(InvalidConfiguration::class);

it('ignores a malformed anchor path configuration rather than half-reading it', function (): void {
    $config = PasskeyConfig::fromArray([
        'attestation_anchors' => ['paths' => ['packed' => 'not-a-list', 3 => ['x.pem'], 'tpm' => [42, '']]],
    ]);

    expect($config->attestationAnchorPaths)->toBe([])
        ->and($config->anchorPathsFor('packed'))->toBe([]);
});
