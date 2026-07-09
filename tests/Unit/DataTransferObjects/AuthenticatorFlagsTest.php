<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticatorFlags;

it('decodes an empty flag byte', function (): void {
    $flags = AuthenticatorFlags::fromByte(0x00);

    expect($flags->userPresent)->toBeFalse()
        ->and($flags->userVerified)->toBeFalse()
        ->and($flags->backupEligible)->toBeFalse()
        ->and($flags->backupState)->toBeFalse()
        ->and($flags->attestedCredentialData)->toBeFalse()
        ->and($flags->extensionData)->toBeFalse();
});

it('decodes each individual bit', function (int $byte, string $property): void {
    expect(AuthenticatorFlags::fromByte($byte)->{$property})->toBeTrue();
})->with([
    'user present' => [0x01, 'userPresent'],
    'user verified' => [0x04, 'userVerified'],
    'backup eligible' => [0x08, 'backupEligible'],
    'backup state' => [0x10, 'backupState'],
    'attested credential data' => [0x40, 'attestedCredentialData'],
    'extension data' => [0x80, 'extensionData'],
]);

it('decodes a fully-set flag byte', function (): void {
    $flags = AuthenticatorFlags::fromByte(0xFF);

    expect($flags->userPresent)->toBeTrue()
        ->and($flags->userVerified)->toBeTrue()
        ->and($flags->backupEligible)->toBeTrue()
        ->and($flags->backupState)->toBeTrue()
        ->and($flags->attestedCredentialData)->toBeTrue()
        ->and($flags->extensionData)->toBeTrue();
});
