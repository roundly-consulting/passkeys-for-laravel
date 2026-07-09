<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Passkeys\Actions\GenerateRegistrationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\VerifyRegistrationAction;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Enums\CoseAlgorithm;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Events\PasskeyRegistered;
use RoundlyConsulting\Passkeys\Exceptions\ChallengeExpired;
use RoundlyConsulting\Passkeys\Exceptions\ChallengeMismatch;
use RoundlyConsulting\Passkeys\Exceptions\CredentialAlreadyRegistered;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAuthenticatorData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Exceptions\OriginMismatch;
use RoundlyConsulting\Passkeys\Exceptions\RpIdMismatch;
use RoundlyConsulting\Passkeys\Exceptions\UnsupportedAlgorithm;
use RoundlyConsulting\Passkeys\Exceptions\UserVerificationRequired;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

/**
 * @param  array<string, mixed>  $overrides
 */
function register(User $user, WebAuthnVectors $vectors, array $overrides = []): Passkey
{
    $options = app(GenerateRegistrationOptionsAction::class)->execute($user);

    $payload = $vectors->registrationResponse(array_merge([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ], $overrides));

    return app(VerifyRegistrationAction::class)->execute($user, RegistrationResponseData::fromArray($payload));
}

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Ada', 'email' => 'ada@example.com']);
});

it('registers a real ES256 credential end to end', function (): void {
    Event::fake([PasskeyRegistered::class]);

    $passkey = register($this->user, WebAuthnVectors::es256());

    expect($passkey->exists)->toBeTrue()
        ->and($passkey->authenticatable->is($this->user))->toBeTrue()
        ->and($passkey->attestation_format)->toBe('none')
        ->and($passkey->transports)->toBe(['internal', 'hybrid'])
        ->and($passkey->aaguid)->not->toBeNull();

    Event::assertDispatched(PasskeyRegistered::class);
});

it('registers a real RS256 credential end to end', function (): void {
    $passkey = register($this->user, WebAuthnVectors::rs256());

    expect($passkey->exists)->toBeTrue();
});

it('stores the COSE public key so a later assertion can verify against it', function (): void {
    $vectors = WebAuthnVectors::es256();

    $passkey = register($this->user, $vectors);

    expect(base64_decode($passkey->public_key, true))->toBe($vectors->coseKey());
});

it('normalises an all-zero aaguid to null', function (): void {
    $passkey = register($this->user, WebAuthnVectors::es256(), ['aaguid' => str_repeat("\x00", 16)]);

    expect($passkey->aaguid)->toBeNull();
});

it('rejects a client data type that is not webauthn.create', function (): void {
    register($this->user, WebAuthnVectors::es256(), ['type' => 'webauthn.get']);
})->throws(InvalidClientData::class);

it('rejects a mismatched challenge', function (): void {
    $vectors = WebAuthnVectors::es256();
    $options = app(GenerateRegistrationOptionsAction::class)->execute($this->user);
    $payload = $vectors->registrationResponse(['challenge' => 'tampered-challenge', 'ceremonyId' => $options->ceremonyId]);

    app(VerifyRegistrationAction::class)->execute($this->user, RegistrationResponseData::fromArray($payload));
})->throws(ChallengeMismatch::class);

it('rejects a missing or expired ceremony challenge', function (): void {
    $vectors = WebAuthnVectors::es256();
    $payload = $vectors->registrationResponse(['ceremonyId' => 'never-stored']);

    app(VerifyRegistrationAction::class)->execute($this->user, RegistrationResponseData::fromArray($payload));
})->throws(ChallengeExpired::class);

it('rejects a disallowed origin', function (): void {
    register($this->user, WebAuthnVectors::es256(), ['origin' => 'https://evil.example']);
})->throws(OriginMismatch::class);

it('rejects a cross-origin ceremony by default', function (): void {
    register($this->user, WebAuthnVectors::es256(), ['crossOrigin' => true]);
})->throws(OriginMismatch::class);

it('allows a cross-origin ceremony when configured', function (): void {
    config()->set('passkeys.allow_cross_origin', true);
    app()->forgetInstance(PasskeyConfig::class);

    $passkey = register($this->user, WebAuthnVectors::es256(), ['crossOrigin' => true]);

    expect($passkey->exists)->toBeTrue();
});

it('rejects a mismatched rp id hash', function (): void {
    register($this->user, WebAuthnVectors::es256(), ['rpId' => 'attacker.test']);
})->throws(RpIdMismatch::class);

it('rejects a response with the user-presence flag cleared', function (): void {
    register($this->user, WebAuthnVectors::es256(), ['flags' => 0x44]); // UV|AT, no UP
})->throws(InvalidAuthenticatorData::class);

it('rejects a response without user verification when it is required', function (): void {
    register($this->user, WebAuthnVectors::es256(), ['flags' => 0x41]); // UP|AT, no UV
})->throws(UserVerificationRequired::class);

it('rejects inconsistent backup-state flags', function (): void {
    register($this->user, WebAuthnVectors::es256(), ['flags' => 0x55]); // UP|UV|BS|AT, no BE
})->throws(InvalidAuthenticatorData::class);

it('rejects an algorithm that is not offered', function (): void {
    config()->set('passkeys.algorithms', [CoseAlgorithm::RS256->value]);
    app()->forgetInstance(PasskeyConfig::class);

    register($this->user, WebAuthnVectors::es256());
})->throws(UnsupportedAlgorithm::class);

it('rejects a credential that is already registered', function (): void {
    $vectors = WebAuthnVectors::es256();
    register($this->user, $vectors);

    register($this->user, $vectors);
})->throws(CredentialAlreadyRegistered::class);

it('honours user-verification set to discouraged', function (): void {
    config()->set('passkeys.user_verification', UserVerification::Discouraged->value);
    app()->forgetInstance(PasskeyConfig::class);

    $passkey = register($this->user, WebAuthnVectors::es256(), ['flags' => 0x41]); // UP|AT, no UV

    expect($passkey->exists)->toBeTrue();
});
