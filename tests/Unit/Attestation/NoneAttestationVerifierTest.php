<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Passkeys\Attestation\NoneAttestationVerifier;
use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\Enums\AttestationType;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAttestation;

/**
 * Attestation trust stays here even though the parsed authenticator data is
 * crypto's — the statement is a trust decision, not an algorithm.
 */
function parsedStub(): AuthenticatorData
{
    // rpIdHash ‖ flags (UP|UV) ‖ signCount — no attested credential data.
    return AuthenticatorData::parse(str_repeat("\x00", 32).chr(0x05).pack('N', 0));
}

it('reports the none attestation type for an empty statement', function (): void {
    $result = (new NoneAttestationVerifier)->verify(
        new AttestationObject(format: 'none', statement: [], authenticatorData: 'raw'),
        parsedStub(),
        'hash',
    );

    expect($result->format)->toBe('none')
        ->and($result->type)->toBe(AttestationType::None)
        ->and($result->type->isChained())->toBeFalse()
        ->and($result->trustPath)->toBeNull();
});

it('rejects a none statement that carries data', function (): void {
    (new NoneAttestationVerifier)->verify(
        new AttestationObject(format: 'none', statement: ['sig' => 'x'], authenticatorData: 'raw'),
        parsedStub(),
        'hash',
    );
})->throws(InvalidAttestation::class, 'empty map');
