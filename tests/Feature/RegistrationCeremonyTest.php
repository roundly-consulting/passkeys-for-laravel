<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Crypto\Cose\CoseAlgorithm;
use RoundlyConsulting\Passkeys\Actions\GenerateAuthenticationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\GenerateRegistrationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\VerifyRegistrationAction;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
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
use RoundlyConsulting\Passkeys\Testing\VirtualAuthenticator;
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
    $authenticator = VirtualAuthenticator::es256();

    $options = app(GenerateRegistrationOptionsAction::class)->execute($this->user);
    $passkey = app(VerifyRegistrationAction::class)->execute($this->user, $authenticator->register($options));

    expect($passkey->exists)->toBeTrue()
        ->and($passkey->authenticatable->is($this->user))->toBeTrue()
        ->and($passkey->credential_id)->toBe($authenticator->credentialId())
        ->and($passkey->attestation_format)->toBe('none')
        ->and($passkey->transports)->toBe(['internal'])
        // The virtual authenticator discloses no AAGUID, which is stored as null.
        ->and($passkey->aaguid)->toBeNull();

    Event::assertDispatched(PasskeyRegistered::class);
});

it('stores the registering account\'s handle on the credential', function (): void {
    $authenticator = VirtualAuthenticator::es256();

    $options = app(GenerateRegistrationOptionsAction::class)->execute($this->user);
    $passkey = app(VerifyRegistrationAction::class)->execute($this->user, $authenticator->register($options, residentKey: false));

    expect($passkey->user_handle)->toBe($this->user->passkeyUserHandle());
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

it('stores a friendly name passed to register', function (): void {
    $options = app(GenerateRegistrationOptionsAction::class)->execute($this->user);
    $vectors = WebAuthnVectors::es256();
    $payload = $vectors->registrationResponse(['challenge' => $options->challenge, 'ceremonyId' => $options->ceremonyId]);

    $passkey = app(VerifyRegistrationAction::class)->execute(
        $this->user,
        RegistrationResponseData::fromArray($payload),
        'Security key',
    );

    expect($passkey->name)->toBe('Security key');
});

it('rejects a registration response for a user other than the challenge target', function (): void {
    $other = User::query()->create(['name' => 'Bob', 'email' => 'bob@example.com']);

    // Options (and the user-handle binding) are minted for $other…
    $options = app(GenerateRegistrationOptionsAction::class)->execute($other);
    $vectors = WebAuthnVectors::es256();
    $payload = $vectors->registrationResponse(['challenge' => $options->challenge, 'ceremonyId' => $options->ceremonyId]);

    // …but the host verifies against a different user.
    app(VerifyRegistrationAction::class)->execute($this->user, RegistrationResponseData::fromArray($payload));
})->throws(ChallengeMismatch::class);

it('skips the user-handle binding when the challenge recorded none', function (): void {
    $vectors = WebAuthnVectors::es256();
    $options = app(GenerateRegistrationOptionsAction::class)->execute($this->user);

    // Overwrite the stored challenge with one that recorded no user-handle binding.
    app(ChallengeRepository::class)->put($options->ceremonyId, new ChallengeData(
        challenge: $options->challenge,
        userVerification: UserVerification::Required,
        algorithms: [CoseAlgorithm::ES256->value, CoseAlgorithm::RS256->value],
    ), 60);

    $payload = $vectors->registrationResponse(['challenge' => $options->challenge, 'ceremonyId' => $options->ceremonyId]);
    $passkey = app(VerifyRegistrationAction::class)->execute($this->user, RegistrationResponseData::fromArray($payload));

    expect($passkey->exists)->toBeTrue();
});

it('rejects an authentication challenge presented to the registration verifier', function (): void {
    $options = app(GenerateAuthenticationOptionsAction::class)->execute();
    $vectors = WebAuthnVectors::es256();
    $payload = $vectors->registrationResponse(['challenge' => $options->challenge, 'ceremonyId' => $options->ceremonyId]);

    app(VerifyRegistrationAction::class)->execute($this->user, RegistrationResponseData::fromArray($payload));
})->throws(ChallengeMismatch::class);

it('registers a long roaming-key credential id end to end', function (): void {
    $vectors = WebAuthnVectors::es256()->withCredentialId(random_bytes(1023));

    $passkey = register($this->user, $vectors);

    expect(strlen($passkey->credential_id))->toBeGreaterThan(1000)
        ->and($passkey->exists)->toBeTrue();

    // Re-registering the same long id is still rejected as a duplicate.
    expect(fn () => register($this->user, $vectors))->toThrow(CredentialAlreadyRegistered::class);
});

it('refuses a wire fmt that is not a WebAuthn format identifier, under the default ignore trust too', function (string $format): void {
    expect(fn () => register($this->user, WebAuthnVectors::es256(), ['fmt' => $format]))
        ->toThrow(InvalidClientData::class);

    expect(Passkey::query()->count())->toBe(0);
})->with([
    'longer than 32 octets' => [str_repeat('x', 400)],
    'empty' => [''],
    'a double quote' => ['pack"ed'],
    'a backslash' => ['pack\\ed'],
    'a space' => ['pack ed'],
    'non-ASCII' => ['packéd'],
]);

it('records any well-formed format identifier under the default ignore trust', function (string $format): void {
    expect(register($this->user, WebAuthnVectors::es256(), ['fmt' => $format])->attestation_format)->toBe($format);
})->with([
    'a registered format' => ['fido-u2f'],
    'exactly 32 octets' => [str_repeat('a', 32)],
    'a reverse-domain name' => ['com.example.fmt'],
]);
