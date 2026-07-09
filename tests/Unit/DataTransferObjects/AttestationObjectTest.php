<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;

it('builds from a decoded attestation map', function (): void {
    $object = AttestationObject::fromDecoded([
        'fmt' => 'none',
        'attStmt' => ['x' => 1],
        'authData' => 'raw-bytes',
    ]);

    expect($object->format)->toBe('none')
        ->and($object->statement)->toBe(['x' => 1])
        ->and($object->authenticatorData)->toBe('raw-bytes');
});

it('defaults an absent attestation statement to an empty array', function (): void {
    $object = AttestationObject::fromDecoded(['fmt' => 'none', 'authData' => 'raw']);

    expect($object->statement)->toBe([]);
});

it('rejects a non-array decode', function (): void {
    AttestationObject::fromDecoded('nope');
})->throws(InvalidClientData::class);

it('rejects a map with the wrong member types', function (array $decoded): void {
    AttestationObject::fromDecoded($decoded);
})->with([
    'non-string fmt' => [['fmt' => 1, 'authData' => 'raw']],
    'non-string authData' => [['fmt' => 'none', 'authData' => 5]],
    'non-array attStmt' => [['fmt' => 'none', 'authData' => 'raw', 'attStmt' => 'x']],
])->throws(InvalidClientData::class);
