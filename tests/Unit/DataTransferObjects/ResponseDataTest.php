<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Support\Base64Url;

it('decodes a registration response payload into raw bytes', function (): void {
    $payload = [
        'id' => Base64Url::encode('cred-id'),
        'rawId' => Base64Url::encode('cred-id'),
        'response' => [
            'clientDataJSON' => Base64Url::encode('{"type":"webauthn.create"}'),
            'attestationObject' => Base64Url::encode('attestation'),
            'transports' => ['internal', 'nfc', 5],
        ],
        'ceremonyId' => 'ceremony-x',
    ];

    $data = RegistrationResponseData::fromArray($payload);

    expect($data->rawId)->toBe('cred-id')
        ->and($data->clientDataJson)->toBe('{"type":"webauthn.create"}')
        ->and($data->attestationObject)->toBe('attestation')
        ->and($data->transports)->toBe(['internal', 'nfc'])
        ->and($data->ceremonyId)->toBe('ceremony-x');
});

it('falls back to the id member when rawId is absent for registration', function (): void {
    $data = RegistrationResponseData::fromArray([
        'id' => Base64Url::encode('fallback'),
        'response' => [
            'clientDataJSON' => Base64Url::encode('{}'),
            'attestationObject' => Base64Url::encode('x'),
        ],
    ]);

    expect($data->rawId)->toBe('fallback')
        ->and($data->transports)->toBe([])
        ->and($data->ceremonyId)->toBeNull();
});

it('rejects a registration payload without a response object', function (): void {
    RegistrationResponseData::fromArray(['id' => 'x']);
})->throws(InvalidClientData::class);

it('rejects a registration payload missing binary members', function (): void {
    RegistrationResponseData::fromArray(['id' => 'x', 'response' => ['clientDataJSON' => 5]]);
})->throws(InvalidClientData::class);

it('decodes an authentication response payload into raw bytes', function (): void {
    $data = AuthenticationResponseData::fromArray([
        'rawId' => Base64Url::encode('cred'),
        'response' => [
            'clientDataJSON' => Base64Url::encode('{"type":"webauthn.get"}'),
            'authenticatorData' => Base64Url::encode('authdata'),
            'signature' => Base64Url::encode('sig'),
            'userHandle' => Base64Url::encode('handle'),
        ],
        'ceremonyId' => 'ceremony-y',
    ]);

    expect($data->rawId)->toBe('cred')
        ->and($data->clientDataJson)->toBe('{"type":"webauthn.get"}')
        ->and($data->authenticatorData)->toBe('authdata')
        ->and($data->signature)->toBe('sig')
        ->and($data->userHandle)->toBe('handle')
        ->and($data->ceremonyId)->toBe('ceremony-y');
});

it('treats an empty user handle as null', function (): void {
    $data = AuthenticationResponseData::fromArray([
        'rawId' => Base64Url::encode('cred'),
        'response' => [
            'clientDataJSON' => Base64Url::encode('{}'),
            'authenticatorData' => Base64Url::encode('a'),
            'signature' => Base64Url::encode('s'),
            'userHandle' => '',
        ],
    ]);

    expect($data->userHandle)->toBeNull();
});

it('rejects an authentication payload without a response object', function (): void {
    AuthenticationResponseData::fromArray(['rawId' => 'x']);
})->throws(InvalidClientData::class);

it('rejects an authentication payload missing binary members', function (): void {
    AuthenticationResponseData::fromArray(['rawId' => 'x', 'response' => ['clientDataJSON' => 'a']]);
})->throws(InvalidClientData::class);
