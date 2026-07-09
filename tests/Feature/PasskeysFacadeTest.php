<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\PasskeyManager;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Alan', 'email' => 'alan@example.com']);
});

it('resolves the manager as a singleton behind the facade', function (): void {
    expect(app(PasskeyManager::class))->toBe(app(PasskeyManager::class));
});

it('runs a full register then authenticate flow through the facade', function (): void {
    $vectors = WebAuthnVectors::es256();

    $creationOptions = Passkeys::registrationOptions($this->user);
    expect($creationOptions)->toBeInstanceOf(CreationOptionsData::class);

    $registration = $vectors->registrationResponse([
        'challenge' => $creationOptions->challenge,
        'ceremonyId' => $creationOptions->ceremonyId,
    ]);

    $passkey = Passkeys::register($this->user, RegistrationResponseData::fromArray($registration));
    expect($passkey)->toBeInstanceOf(Passkey::class);

    $requestOptions = Passkeys::authenticationOptions();
    expect($requestOptions)->toBeInstanceOf(RequestOptionsData::class);

    $assertion = $vectors->assertionResponse([
        'challenge' => $requestOptions->challenge,
        'ceremonyId' => $requestOptions->ceremonyId,
        'signCount' => 4,
    ]);

    $authenticated = Passkeys::authenticate(AuthenticationResponseData::fromArray($assertion));

    expect($authenticated->is($passkey))->toBeTrue()
        ->and($authenticated->sign_count)->toBe(4);
});

it('honours per-call registration overrides', function (): void {
    $options = Passkeys::registrationOptions($this->user, new RegistrationOptionsOverrides(
        userVerification: UserVerification::Discouraged,
        attestation: AttestationConveyance::Direct,
        timeoutMs: 12_000,
    ));

    expect($options->userVerification)->toBe(UserVerification::Discouraged)
        ->and($options->attestation)->toBe(AttestationConveyance::Direct)
        ->and($options->timeoutMs)->toBe(12_000);
});

it('scopes authentication options to a known user', function (): void {
    $vectors = WebAuthnVectors::es256();
    $creation = Passkeys::registrationOptions($this->user);
    Passkeys::register($this->user, RegistrationResponseData::fromArray(
        $vectors->registrationResponse(['challenge' => $creation->challenge, 'ceremonyId' => $creation->ceremonyId]),
    ));

    $scoped = Passkeys::authenticationOptions($this->user);
    $usernameless = Passkeys::authenticationOptions();

    expect($scoped->allowCredentials)->toHaveCount(1)
        ->and($usernameless->allowCredentials)->toBe([]);
});

it('serialises creation options into the browser JSON shape', function (): void {
    $options = Passkeys::registrationOptions($this->user);
    $json = $options->jsonSerialize();

    expect($json)->toHaveKey('publicKey')
        ->and($json['publicKey'])->toHaveKeys(['rp', 'user', 'challenge', 'pubKeyCredParams', 'authenticatorSelection'])
        ->and($json['publicKey']['rp']['id'])->toBe('example.com')
        ->and($json['publicKey']['authenticatorSelection']['residentKey'])->toBe('required');
});
