<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\DataTransferObjects\ClientData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;

it('parses a well-formed client data json object', function (): void {
    $data = ClientData::fromJson((string) json_encode([
        'type' => 'webauthn.create',
        'challenge' => 'Y2hhbGxlbmdl',
        'origin' => 'https://example.com',
        'crossOrigin' => true,
    ]));

    expect($data->type)->toBe('webauthn.create')
        ->and($data->challenge)->toBe('Y2hhbGxlbmdl')
        ->and($data->origin)->toBe('https://example.com')
        ->and($data->crossOrigin)->toBeTrue();
});

it('defaults crossOrigin to false when absent', function (): void {
    $data = ClientData::fromJson((string) json_encode([
        'type' => 'webauthn.get',
        'challenge' => 'abc',
        'origin' => 'https://example.com',
    ]));

    expect($data->crossOrigin)->toBeFalse();
});

it('rejects invalid json', function (): void {
    ClientData::fromJson('{not json');
})->throws(InvalidClientData::class);

it('rejects json that is not an object', function (): void {
    ClientData::fromJson('"a string"');
})->throws(InvalidClientData::class);

it('rejects client data missing required members', function (array $payload): void {
    ClientData::fromJson((string) json_encode($payload));
})->with([
    'no type' => [['challenge' => 'a', 'origin' => 'https://example.com']],
    'no challenge' => [['type' => 'webauthn.get', 'origin' => 'https://example.com']],
    'no origin' => [['type' => 'webauthn.get', 'challenge' => 'a']],
    'non-string type' => [['type' => 5, 'challenge' => 'a', 'origin' => 'https://example.com']],
])->throws(InvalidClientData::class);
