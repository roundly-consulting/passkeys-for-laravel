<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\Contracts\PasskeyService;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Exceptions\UserVerificationRequired;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

/**
 * Per-ceremony authentication overrides: the requirement travels with the challenge, so
 * the verifier enforces exactly what the options promised — not the global default.
 */
function overridesUseConfiguredVerification(UserVerification $verification): void
{
    config()->set('passkeys.user_verification', $verification->value);

    // The config was resolved during enrolment, so drop it and the manager for the
    // new default to take effect.
    app()->forgetInstance(PasskeyConfig::class);
    app()->forgetInstance(PasskeyService::class);
    Passkeys::clearResolvedInstances();
}

function overridesAssertUpOnly(RequestOptionsData $options, WebAuthnVectors $vectors): Passkey
{
    return Passkeys::authenticate(AuthenticationResponseData::fromArray($vectors->assertionResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
        'flags' => 0x01, // UP without UV
        'signCount' => 3,
    ])));
}

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Sam', 'email' => 'sam@example.com']);
    $this->vectors = WebAuthnVectors::es256();

    $options = $this->user->passkeyRegistrationOptions();
    $this->user->registerPasskey(RegistrationResponseData::fromArray($this->vectors->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ])));
});

it('rejects a presence-only assertion when the override requires verification over a preferred default', function (): void {
    overridesUseConfiguredVerification(UserVerification::Preferred);

    $options = Passkeys::for($this->user)->authenticationOptions(new AuthenticationOptionsOverrides(userVerification: UserVerification::Required));

    expect($options->jsonSerialize()['publicKey']['userVerification'])->toBe('required');

    overridesAssertUpOnly($options, $this->vectors);
})->throws(UserVerificationRequired::class);

it('accepts a presence-only assertion under the preferred default without an override', function (): void {
    overridesUseConfiguredVerification(UserVerification::Preferred);

    expect(overridesAssertUpOnly(Passkeys::for($this->user)->authenticationOptions(), $this->vectors)->sign_count)->toBe(3);
});

it('lets an override relax verification for a single ceremony', function (): void {
    // The configured default is `required`.
    $options = Passkeys::authenticationOptions(overrides: new AuthenticationOptionsOverrides(userVerification: UserVerification::Discouraged));

    expect(overridesAssertUpOnly($options, $this->vectors)->sign_count)->toBe(3);
});

it('stores the overridden requirement with the challenge', function (): void {
    $options = Passkeys::authenticationOptions(overrides: new AuthenticationOptionsOverrides(userVerification: UserVerification::Preferred));

    expect(app(ChallengeRepository::class)->pull($options->ceremonyId)?->userVerification)->toBe(UserVerification::Preferred);
});

it('puts the overridden timeout into the options json', function (): void {
    $options = Passkeys::for($this->user)->authenticationOptions(new AuthenticationOptionsOverrides(timeoutMs: 15_000));

    expect($options->jsonSerialize()['publicKey']['timeout'])->toBe(15_000)
        ->and($options->timeoutMs)->toBe(15_000);
});

it('falls back to the configured timeout and verification', function (): void {
    $options = Passkeys::authenticationOptions(overrides: new AuthenticationOptionsOverrides);

    expect($options->timeoutMs)->toBe(app(PasskeyConfig::class)->timeoutMs)
        ->and($options->userVerification)->toBe(UserVerification::Required);
});

it('forwards overrides through the user-model verb', function (): void {
    $options = $this->user->passkeyAuthenticationOptions(new AuthenticationOptionsOverrides(timeoutMs: 9_000));

    expect($options->timeoutMs)->toBe(9_000)
        ->and($options->allowCredentials)->toHaveCount(1);
});
