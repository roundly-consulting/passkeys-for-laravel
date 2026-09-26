<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;
use RoundlyConsulting\Passkeys\Enums\CeremonyType;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Models\Passkey;

it('round-trips the user binding and the allowed credential hashes', function (): void {
    $hashes = [Passkey::hashCredentialId('cred-a'), Passkey::hashCredentialId('cred-b')];

    $data = new ChallengeData(
        challenge: 'abc',
        userVerification: UserVerification::Required,
        algorithms: [-7],
        type: CeremonyType::Authentication,
        userHandle: 'handle-a',
        allowedCredentialHashes: $hashes,
    );

    $restored = ChallengeData::fromArray($data->toArray());

    expect($data->toArray()['allowed_credential_hashes'])->toBe($hashes)
        ->and($restored->userHandle)->toBe('handle-a')
        ->and($restored->allowedCredentialHashes)->toBe($hashes)
        ->and($restored->type)->toBe(CeremonyType::Authentication)
        ->and($restored->userVerification)->toBe(UserVerification::Required);
});

it('defaults to no allow-list for a discoverable ceremony', function (): void {
    $data = new ChallengeData(challenge: 'x', userVerification: UserVerification::Preferred, algorithms: [], type: CeremonyType::Authentication);

    expect($data->allowedCredentialHashes)->toBe([])
        ->and($data->toArray()['allowed_credential_hashes'])->toBe([]);
});

it('tolerates a challenge stored before the allow-list existed', function (): void {
    $restored = ChallengeData::fromArray([
        'challenge' => 'x',
        'user_verification' => 'required',
        'algorithms' => [-7],
        'type' => 'authentication',
        'user_handle' => 'h',
    ]);

    expect($restored->allowedCredentialHashes)->toBe([])
        ->and($restored->userHandle)->toBe('h');
});

it('drops non-string allow-list members and reindexes the list', function (): void {
    $restored = ChallengeData::fromArray([
        'challenge' => 'x',
        'allowed_credential_hashes' => ['a', 5, null, 'b'],
    ]);

    expect($restored->allowedCredentialHashes)->toBe(['a', 'b']);
});

it('ignores an allow-list that is not a list', function (): void {
    expect(ChallengeData::fromArray(['allowed_credential_hashes' => 'nope'])->allowedCredentialHashes)->toBe([]);
});
