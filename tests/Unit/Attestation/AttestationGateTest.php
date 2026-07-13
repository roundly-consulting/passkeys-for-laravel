<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Passkeys\Attestation\AttestationAnchors;
use RoundlyConsulting\Passkeys\Attestation\AttestationGate;
use RoundlyConsulting\Passkeys\Attestation\AttestationResult;
use RoundlyConsulting\Passkeys\Attestation\AttestationVerifier;
use RoundlyConsulting\Passkeys\Attestation\AttestationVerifierRegistry;
use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\Enums\AttestationType;

/**
 * A verifier that records whether it was ever asked to do any maths. The default
 * (`ignore`) posture must never invoke one.
 */
final class SpyVerifier implements AttestationVerifier
{
    public int $calls = 0;

    public function verify(
        AttestationObject $attestation,
        AuthenticatorData $authenticatorData,
        string $clientDataHash,
    ): AttestationResult {
        $this->calls++;

        return AttestationResult::none($attestation->format);
    }
}

/**
 * @param  array<string, mixed>  $config
 */
function gateWith(SpyVerifier $spy, array $config = []): AttestationGate
{
    $typed = PasskeyConfig::fromArray($config);

    return new AttestationGate(
        new AttestationVerifierRegistry(['none' => $spy, 'packed' => $spy]),
        new AttestationAnchors($typed),
        $typed,
    );
}

function gateAuthData(): AuthenticatorData
{
    return AuthenticatorData::parse(str_repeat("\x00", 32).chr(0x05).pack('N', 0));
}

it('short-circuits under the default posture without invoking any verifier', function (string $format): void {
    $spy = new SpyVerifier;

    $result = gateWith($spy)->verify(
        new AttestationObject(format: $format, statement: ['sig' => 'nonsense'], authenticatorData: 'raw'),
        gateAuthData(),
        'hash',
    );

    expect($spy->calls)->toBe(0)
        ->and($result->type)->toBe(AttestationType::None)
        ->and($result->format)->toBe($format);
})->with(['none', 'packed', 'android-safetynet']);

it('invokes the format verifier once reject_unknown_fmt is on', function (): void {
    $spy = new SpyVerifier;

    gateWith($spy, ['reject_unknown_fmt' => true])->verify(
        new AttestationObject(format: 'packed', statement: [], authenticatorData: 'raw'),
        gateAuthData(),
        'hash',
    );

    expect($spy->calls)->toBe(1);
});

it('lists the supported formats when it refuses an unknown one', function (): void {
    $registry = new AttestationVerifierRegistry(['none' => new SpyVerifier]);

    expect($registry->formats())->toBe(['none'])
        ->and($registry->for('nope'))->toBeNull();
});
