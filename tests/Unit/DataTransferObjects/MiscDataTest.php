<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\CeremonyType;
use RoundlyConsulting\Passkeys\Enums\UserVerification;

it('serialises challenge data to an array and back', function (): void {
    $data = new ChallengeData(
        challenge: 'abc',
        userVerification: UserVerification::Preferred,
        algorithms: [-7],
        type: CeremonyType::Registration,
        userHandle: 'handle',
    );

    expect($data->toArray())->toBe([
        'challenge' => 'abc',
        'user_verification' => 'preferred',
        'algorithms' => [-7],
        'type' => 'registration',
        'user_handle' => 'handle',
        'allowed_credential_hashes' => [],
    ]);
});

it('restores challenge data defensively from a malformed array', function (): void {
    $data = ChallengeData::fromArray([
        'challenge' => 5,
        'user_verification' => null,
        'algorithms' => [-7, 'bad', -257],
        'type' => 123,
        'user_handle' => 42,
    ]);

    expect($data->challenge)->toBe('')
        ->and($data->userVerification)->toBe(UserVerification::Preferred)
        ->and($data->algorithms)->toBe([-7, -257])
        ->and($data->type)->toBe(CeremonyType::Registration)
        ->and($data->userHandle)->toBeNull();
});

it('round-trips the ceremony type through serialisation', function (): void {
    $data = new ChallengeData(
        challenge: 'x',
        userVerification: UserVerification::Required,
        algorithms: [],
        type: CeremonyType::Authentication,
    );

    expect(ChallengeData::fromArray($data->toArray())->type)->toBe(CeremonyType::Authentication);
});

it('carries a null user handle for an authentication ceremony', function (): void {
    $data = new ChallengeData(
        challenge: 'x',
        userVerification: UserVerification::Required,
        algorithms: [],
        type: CeremonyType::Authentication,
    );

    expect($data->toArray()['user_handle'])->toBeNull();
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
