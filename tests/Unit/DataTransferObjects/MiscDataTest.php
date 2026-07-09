<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CoseKeyData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\CoseAlgorithm;
use RoundlyConsulting\Passkeys\Enums\UserVerification;

it('serialises challenge data to an array and back', function (): void {
    $data = new ChallengeData(
        challenge: 'abc',
        userVerification: UserVerification::Preferred,
        algorithms: [-7],
        userHandle: 'handle',
    );

    expect($data->toArray())->toBe([
        'challenge' => 'abc',
        'user_verification' => 'preferred',
        'algorithms' => [-7],
        'user_handle' => 'handle',
    ]);
});

it('restores challenge data defensively from a malformed array', function (): void {
    $data = ChallengeData::fromArray([
        'challenge' => 5,
        'user_verification' => null,
        'algorithms' => [-7, 'bad', -257],
        'user_handle' => 42,
    ]);

    expect($data->challenge)->toBe('')
        ->and($data->userVerification)->toBe(UserVerification::Preferred)
        ->and($data->algorithms)->toBe([-7, -257])
        ->and($data->userHandle)->toBeNull();
});

it('carries a null user handle for an authentication ceremony', function (): void {
    $data = new ChallengeData(challenge: 'x', userVerification: UserVerification::Required, algorithms: []);

    expect($data->toArray()['user_handle'])->toBeNull();
});

it('holds ES256 verification material as an SPKI PEM', function (): void {
    $key = new CoseKeyData(algorithm: CoseAlgorithm::ES256, pem: 'pem');

    expect($key->algorithm)->toBe(CoseAlgorithm::ES256)
        ->and($key->pem)->toBe('pem')
        ->and($key->edwardsPublicKey)->toBeNull();
});

it('defaults registration overrides to null members', function (): void {
    $overrides = new RegistrationOptionsOverrides;

    expect($overrides->userVerification)->toBeNull()
        ->and($overrides->attestation)->toBeNull()
        ->and($overrides->timeoutMs)->toBeNull();
});

it('carries registration override values', function (): void {
    $overrides = new RegistrationOptionsOverrides(
        userVerification: UserVerification::Discouraged,
        attestation: AttestationConveyance::Indirect,
        timeoutMs: 5_000,
    );

    expect($overrides->userVerification)->toBe(UserVerification::Discouraged)
        ->and($overrides->attestation)->toBe(AttestationConveyance::Indirect)
        ->and($overrides->timeoutMs)->toBe(5_000);
});
