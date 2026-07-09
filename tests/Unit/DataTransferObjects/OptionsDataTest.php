<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CredentialDescriptor;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Support\Base64Url;

it('serialises a credential descriptor with transports', function (): void {
    $descriptor = new CredentialDescriptor(id: 'raw-id', transports: ['internal', 'hybrid']);

    expect($descriptor->toArray())->toBe([
        'type' => 'public-key',
        'id' => Base64Url::encode('raw-id'),
        'transports' => ['internal', 'hybrid'],
    ]);
});

it('omits the transports key when the list is empty', function (): void {
    $descriptor = new CredentialDescriptor(id: 'raw-id');

    expect($descriptor->toArray())->not->toHaveKey('transports');
});

it('serialises creation options to the browser json shape', function (): void {
    $options = new CreationOptionsData(
        ceremonyId: 'ceremony',
        rpId: 'example.com',
        rpName: 'Example',
        userHandle: 'user-handle',
        userName: 'ada@example.com',
        userDisplayName: 'Ada Lovelace',
        challenge: 'Y2hhbGxlbmdl',
        algorithms: [-7, -257],
        timeoutMs: 60_000,
        attestation: AttestationConveyance::None,
        userVerification: UserVerification::Required,
        excludeCredentials: [new CredentialDescriptor(id: 'old', transports: ['usb'])],
    );

    $json = $options->jsonSerialize();

    expect($json['ceremonyId'])->toBe('ceremony')
        ->and($json['publicKey']['user']['id'])->toBe(Base64Url::encode('user-handle'))
        ->and($json['publicKey']['user']['name'])->toBe('ada@example.com')
        ->and($json['publicKey']['pubKeyCredParams'])->toBe([
            ['type' => 'public-key', 'alg' => -7],
            ['type' => 'public-key', 'alg' => -257],
        ])
        ->and($json['publicKey']['attestation'])->toBe('none')
        ->and($json['publicKey']['excludeCredentials'])->toHaveCount(1)
        ->and($json['publicKey']['authenticatorSelection']['userVerification'])->toBe('required');
});

it('serialises request options to the browser json shape', function (): void {
    $options = new RequestOptionsData(
        ceremonyId: 'ceremony',
        rpId: 'example.com',
        challenge: 'Y2hhbGxlbmdl',
        timeoutMs: 60_000,
        userVerification: UserVerification::Preferred,
        allowCredentials: [new CredentialDescriptor(id: 'cred')],
    );

    $json = $options->jsonSerialize();

    expect($json['publicKey']['rpId'])->toBe('example.com')
        ->and($json['publicKey']['userVerification'])->toBe('preferred')
        ->and($json['publicKey']['allowCredentials'])->toHaveCount(1)
        ->and($json['publicKey']['challenge'])->toBe('Y2hhbGxlbmdl');
});

it('serialises an empty allow-credentials list for usernameless login', function (): void {
    $options = new RequestOptionsData(
        ceremonyId: 'ceremony',
        rpId: 'example.com',
        challenge: 'abc',
        timeoutMs: 1,
        userVerification: UserVerification::Required,
    );

    expect($options->jsonSerialize()['publicKey']['allowCredentials'])->toBe([]);
});

it('is json-encodable end to end', function (): void {
    $options = new RequestOptionsData(
        ceremonyId: 'c',
        rpId: 'example.com',
        challenge: 'abc',
        timeoutMs: 1,
        userVerification: UserVerification::Required,
    );

    expect(json_decode((string) json_encode($options), true))->toHaveKey('publicKey');
});
