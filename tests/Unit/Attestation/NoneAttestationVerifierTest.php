<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Passkeys\Attestation\NoneAttestationVerifier;
use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;

/**
 * Attestation trust stays here even though the parsed authenticator data is
 * crypto's — the statement is a trust decision, not an algorithm.
 */
function parsedStub(): AuthenticatorData
{
    // rpIdHash ‖ flags (UP|UV) ‖ signCount — no attested credential data.
    return AuthenticatorData::parse(str_repeat("\x00", 32).chr(0x05).pack('N', 0));
}

it('records the attestation format without verifying the statement', function (): void {
    $verifier = new NoneAttestationVerifier;
    $attestation = new AttestationObject(format: 'packed', statement: ['sig' => 'x'], authenticatorData: 'raw');

    $verifier->verify($attestation, parsedStub(), 'hash');
})->throwsNoExceptions();

it('accepts the none format when unknown formats are rejected', function (): void {
    $verifier = new NoneAttestationVerifier(rejectUnknownFormat: true);
    $attestation = new AttestationObject(format: 'none', statement: [], authenticatorData: 'raw');

    $verifier->verify($attestation, parsedStub(), 'hash');
})->throwsNoExceptions();

it('rejects a non-none format when unknown formats are rejected', function (): void {
    $verifier = new NoneAttestationVerifier(rejectUnknownFormat: true);
    $attestation = new AttestationObject(format: 'packed', statement: [], authenticatorData: 'raw');

    $verifier->verify($attestation, parsedStub(), 'hash');
})->throws(InvalidClientData::class);
