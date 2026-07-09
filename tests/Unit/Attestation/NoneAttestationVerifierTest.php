<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Attestation\NoneAttestationVerifier;
use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticatorFlags;
use RoundlyConsulting\Passkeys\DataTransferObjects\ParsedAuthenticatorData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;

function parsedStub(): ParsedAuthenticatorData
{
    return new ParsedAuthenticatorData(
        rpIdHash: str_repeat("\x00", 32),
        flags: AuthenticatorFlags::fromByte(0x45),
        signCount: 0,
    );
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
