<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Actions\GenerateAuthenticationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\GenerateRegistrationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\VerifyAuthenticationAction;
use RoundlyConsulting\Passkeys\Actions\VerifyRegistrationAction;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Enums\CeremonyType;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

/**
 * WebAuthn L3 §7.2 steps 5–6: a ceremony minted for a known user may only be completed
 * with a credential that user owns AND that the options offered in allowCredentials. The
 * browser omits `userHandle` for a non-discoverable credential, so before this binding an
 * options call for user A could be finished with user B's passkey.
 */
function boundRegister(User $user, WebAuthnVectors $vectors): Passkey
{
    $options = app(GenerateRegistrationOptionsAction::class)->execute($user);
    $payload = $vectors->registrationResponse(['challenge' => $options->challenge, 'ceremonyId' => $options->ceremonyId]);

    return app(VerifyRegistrationAction::class)->execute($user, RegistrationResponseData::fromArray($payload));
}

function boundAssert(RequestOptionsData $options, WebAuthnVectors $vectors, int $signCount = 5): Passkey
{
    $payload = $vectors->assertionResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
        'signCount' => $signCount,
    ]);

    return app(VerifyAuthenticationAction::class)->execute(AuthenticationResponseData::fromArray($payload));
}

beforeEach(function (): void {
    $this->alice = User::query()->create(['name' => 'Alice', 'email' => 'alice@example.com']);
    $this->bob = User::query()->create(['name' => 'Bob', 'email' => 'bob@example.com']);
    $this->aliceKey = WebAuthnVectors::es256();
    $this->bobKey = WebAuthnVectors::es256();
    $this->alicePasskey = boundRegister($this->alice, $this->aliceKey);
    $this->bobPasskey = boundRegister($this->bob, $this->bobKey);
});

it('binds the stored challenge to the user and the offered credentials', function (): void {
    $options = app(GenerateAuthenticationOptionsAction::class)->execute($this->alice);

    $stored = app(ChallengeRepository::class)->pull($options->ceremonyId);

    expect($stored)->not->toBeNull()
        ->and($stored?->userHandle)->toBe($this->alice->passkeyUserHandle())
        ->and($stored?->allowedCredentialHashes)->toBe([$this->alicePasskey->credential_id_hash])
        ->and($options->allowCredentials)->toHaveCount(1);
});

it('accepts the user\'s own offered credential', function (): void {
    $options = app(GenerateAuthenticationOptionsAction::class)->execute($this->alice);

    expect(boundAssert($options, $this->aliceKey)->is($this->alicePasskey))->toBeTrue();
});

it('refuses another user\'s real credential and leaves its counter untouched', function (): void {
    $options = app(GenerateAuthenticationOptionsAction::class)->execute($this->alice);
    $before = $this->bobPasskey->fresh();

    expect(fn (): Passkey => boundAssert($options, $this->bobKey, signCount: 42))
        ->toThrow(CredentialNotFound::class);

    $after = $this->bobPasskey->fresh();

    expect($after?->sign_count)->toBe($before?->sign_count)
        ->and($after?->last_used_at)->toBeNull();
});

it('refuses the user\'s own credential when it was not offered in allowCredentials', function (): void {
    $options = app(GenerateAuthenticationOptionsAction::class)->execute($this->alice);

    // Enrolled AFTER the options were minted: same owner, same handle, not in the allow-list.
    $late = WebAuthnVectors::es256();
    $latePasskey = boundRegister($this->alice, $late);

    expect(fn (): Passkey => boundAssert($options, $late))->toThrow(CredentialNotFound::class)
        ->and($latePasskey->fresh()?->last_used_at)->toBeNull();
});

it('refuses another user\'s credential on a handle-bound ceremony with no allow-list', function (): void {
    app(ChallengeRepository::class)->put('bound', new ChallengeData(
        challenge: 'Y2hhbGxlbmdlLWJvdW5kLXRvLWFsaWNlLTAwMDAwMA',
        userVerification: UserVerification::Required,
        algorithms: [-7],
        type: CeremonyType::Authentication,
        userHandle: $this->alice->passkeyUserHandle(),
    ), 60);

    $options = new RequestOptionsData('bound', 'example.com', 'Y2hhbGxlbmdlLWJvdW5kLXRvLWFsaWNlLTAwMDAwMA', 60_000, UserVerification::Required);

    expect(fn (): Passkey => boundAssert($options, $this->bobKey))->toThrow(CredentialNotFound::class);
});

it('refuses every credential for a user who has none enrolled', function (): void {
    $carol = User::query()->create(['name' => 'Carol', 'email' => 'carol@example.com']);

    $options = app(GenerateAuthenticationOptionsAction::class)->execute($carol);

    expect($options->allowCredentials)->toBe([])
        ->and(fn (): Passkey => boundAssert($options, $this->bobKey))->toThrow(CredentialNotFound::class);
});

it('keeps a discoverable ceremony open to any registered credential', function (): void {
    $forAlice = app(GenerateAuthenticationOptionsAction::class)->execute();
    $forBob = app(GenerateAuthenticationOptionsAction::class)->execute();

    expect(boundAssert($forAlice, $this->aliceKey)->is($this->alicePasskey))->toBeTrue()
        ->and(boundAssert($forBob, $this->bobKey)->is($this->bobPasskey))->toBeTrue();
});
