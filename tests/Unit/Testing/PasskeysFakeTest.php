<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Passkeys\Contracts\PasskeyService;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationExpectation;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Enums\AuthenticatorAttachment;
use RoundlyConsulting\Passkeys\Enums\ResidentKey;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyAssertionFailed;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Testing\PasskeysFake;
use RoundlyConsulting\Passkeys\Tests\Support\User;

function fakeRegistrationResponse(): RegistrationResponseData
{
    return new RegistrationResponseData(rawId: 'raw', clientDataJson: '{}', attestationObject: 'att');
}

function fakeAssertionResponse(): AuthenticationResponseData
{
    return new AuthenticationResponseData(rawId: 'raw', clientDataJson: '{}', authenticatorData: 'auth', signature: 'sig');
}

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Fake', 'email' => 'fake@example.com']);
    $this->fake = app(PasskeysFake::class);
});

it('returns canned option DTOs with no crypto', function (): void {
    expect($this->fake->for($this->user)->registrationOptions())->toBeInstanceOf(CreationOptionsData::class)
        ->and($this->fake->authenticationOptions())->toBeInstanceOf(RequestOptionsData::class);
});

it('serialises user.id exactly as the real service does', function (): void {
    $real = app(PasskeyService::class)->for($this->user)->registrationOptions()->jsonSerialize();
    $fake = $this->fake->for($this->user)->registrationOptions();

    expect($fake->userHandle)->toBe(Base64Url::decode($this->user->passkeyUserHandle()))
        ->and($fake->jsonSerialize()['publicKey']['user']['id'])->toBe($this->user->passkeyUserHandle())
        ->and($fake->jsonSerialize()['publicKey']['user']['id'])->toBe($real['publicKey']['user']['id']);
});

it('refuses a malformed stored handle in its options, as the real service does', function (): void {
    $this->user->forceFill(['passkey_user_handle' => 'not base64url!'])->save();

    $this->fake->for($this->user)->registrationOptions();
})->throws(InvalidClientData::class);

it('persists a passkey on register and records the call', function (): void {
    $passkey = $this->fake->for($this->user)->register(fakeRegistrationResponse(), 'My Phone');

    expect($passkey->exists)->toBeTrue()
        ->and($passkey->name)->toBe('My Phone')
        ->and($passkey->authenticatable->is($this->user))->toBeTrue();

    $this->fake->assertRegistered();
    $this->fake->assertRegisteredFor($this->user);
    $this->fake->assertRegistrationCount(1);
});

it('throws the programmed exception on register', function (): void {
    $this->fake->failRegistrationWith(CredentialNotFound::make());

    expect(fn (): Passkey => $this->fake->for($this->user)->register(fakeRegistrationResponse()))
        ->toThrow(CredentialNotFound::class);

    $this->fake->assertNothingRegistered();
});

it('accepts registration again after being reset', function (): void {
    $this->fake->failRegistrationWith(CredentialNotFound::make())->acceptRegistration();

    expect($this->fake->for($this->user)->register(fakeRegistrationResponse())->exists)->toBeTrue();
});

it('authenticates as the last registered credential by default', function (): void {
    $registered = $this->fake->for($this->user)->register(fakeRegistrationResponse());

    $authenticated = $this->fake->authenticate(fakeAssertionResponse());

    expect($authenticated->is($registered))->toBeTrue();
    $this->fake->assertAuthenticated();
    $this->fake->assertAuthenticatedFor($this->user);
    $this->fake->assertAuthenticationCount(1);
});

it('authenticates as an explicit credential', function (): void {
    $passkey = Passkey::factory()->forAuthenticatable($this->user)->create();

    $result = $this->fake->authenticatesAs($passkey)->authenticate(fakeAssertionResponse());

    expect($result->is($passkey))->toBeTrue();
});

it('synthesises a credential when authenticating with none seeded', function (): void {
    $result = $this->fake->authenticate(fakeAssertionResponse());

    expect($result)->toBeInstanceOf(Passkey::class)->and($result->exists)->toBeTrue();
});

it('re-accepts authentication after a rejection', function (): void {
    $this->fake->for($this->user)->register(fakeRegistrationResponse());
    $this->fake->rejectAuthentication()->acceptAuthentication();

    expect($this->fake->authenticate(fakeAssertionResponse())->exists)->toBeTrue();
});

it('rejects authentication when programmed to', function (): void {
    $this->fake->rejectAuthentication();

    expect(fn (): Passkey => $this->fake->authenticate(fakeAssertionResponse()))
        ->toThrow(CredentialNotFound::class);

    $this->fake->assertAuthenticationFailed();
});

it('renames and revokes a stored credential through the owner handle', function (): void {
    $passkey = Passkey::factory()->forAuthenticatable($this->user)->create();

    $this->fake->for($this->user)->rename($passkey, 'Renamed');
    expect($passkey->refresh()->name)->toBe('Renamed');

    $this->fake->for($this->user)->revoke($passkey);
    expect($passkey->refresh()->trashed())->toBeTrue();
});

it('fails assertRegistered when nothing registered', function (): void {
    expect(fn () => $this->fake->assertRegistered())->toThrow(PasskeyAssertionFailed::class);
    expect(fn () => $this->fake->assertRegisteredFor($this->user))->toThrow(PasskeyAssertionFailed::class);
});

it('fails assertNothingRegistered when a registration happened', function (): void {
    $this->fake->for($this->user)->register(fakeRegistrationResponse());

    expect(fn () => $this->fake->assertNothingRegistered())->toThrow(PasskeyAssertionFailed::class);
});

it('fails assertAuthenticated when nothing authenticated', function (): void {
    expect(fn () => $this->fake->assertAuthenticated())->toThrow(PasskeyAssertionFailed::class);
    expect(fn () => $this->fake->assertAuthenticatedFor($this->user))->toThrow(PasskeyAssertionFailed::class);
    expect(fn () => $this->fake->assertAuthenticationFailed())->toThrow(PasskeyAssertionFailed::class);
});

it('fails the count assertions on a mismatch', function (): void {
    expect(fn () => $this->fake->assertRegistrationCount(1))->toThrow(PasskeyAssertionFailed::class);
    expect(fn () => $this->fake->assertAuthenticationCount(1))->toThrow(PasskeyAssertionFailed::class);
});

it('does not match a registration for a different user', function (): void {
    $other = User::query()->create(['name' => 'Other', 'email' => 'other@example.com']);
    $this->fake->for($this->user)->register(fakeRegistrationResponse());

    expect(fn () => $this->fake->assertRegisteredFor($other))->toThrow(PasskeyAssertionFailed::class);
});

it('honours authentication overrides in the canned options', function (): void {
    $options = $this->fake->for($this->user)->authenticationOptions(new AuthenticationOptionsOverrides(userVerification: UserVerification::Preferred, timeoutMs: 5_000));

    expect($options->userVerification)->toBe(UserVerification::Preferred)
        ->and($options->timeoutMs)->toBe(5_000);
});

it('refuses a credential that misses the owner expectation, recording a failure', function (): void {
    $this->fake->for($this->user)->register(fakeRegistrationResponse());

    expect(fn (): Passkey => $this->fake->authenticate(fakeAssertionResponse(), AuthenticationExpectation::ownerType('client')))
        ->toThrow(CredentialNotFound::class);

    $this->fake->assertAuthenticationFailed();
    $this->fake->assertAuthenticationCount(1);
});

it('authenticates a credential that meets the owner expectation', function (): void {
    $this->fake->for($this->user)->register(fakeRegistrationResponse());

    $passkey = $this->fake->authenticate(fakeAssertionResponse(), AuthenticationExpectation::owner($this->user));

    expect($passkey->authenticatable->is($this->user))->toBeTrue();
    $this->fake->assertAuthenticatedFor($this->user);
});

it('honours the registration overrides the real options honour', function (): void {
    $overrides = new RegistrationOptionsOverrides(
        timeoutMs: 5_000,
        residentKey: ResidentKey::Preferred,
        authenticatorAttachment: AuthenticatorAttachment::Platform,
    );

    $real = app(PasskeyService::class)->for($this->user)->registrationOptions($overrides)->jsonSerialize()['publicKey'];
    $fake = $this->fake->for($this->user)->registrationOptions($overrides)->jsonSerialize()['publicKey'];

    expect($fake['timeout'])->toBe(5_000)
        ->and($fake['authenticatorSelection']['residentKey'])->toBe('preferred')
        ->and($fake['authenticatorSelection']['authenticatorAttachment'])->toBe('platform')
        ->and($fake['authenticatorSelection'])->toBe($real['authenticatorSelection'])
        ->and($fake['timeout'])->toBe($real['timeout']);
});

it('lists the account\'s active passkeys in exclude and allow lists, like the real options', function (): void {
    $active = Passkey::factory()->forAuthenticatable($this->user)->create();
    Passkey::factory()->forAuthenticatable($this->user)->create()->delete();
    Passkey::factory()->create(); // another account's

    $real = app(PasskeyService::class)->for($this->user);
    $fake = $this->fake->for($this->user);

    expect($fake->registrationOptions()->excludeCredentials)->toHaveCount(1)
        ->toEqual($real->registrationOptions()->excludeCredentials)
        ->and($fake->authenticationOptions()->allowCredentials)->toHaveCount(1)
        ->toEqual($real->authenticationOptions()->allowCredentials)
        ->and($fake->authenticationOptions()->allowCredentials[0]->id)->toBe(Base64Url::decode($active->credential_id))
        // The flat, usernameless request names no account, so it offers no credential.
        ->and($this->fake->authenticationOptions()->allowCredentials)->toBe([]);
});

it('takes its option defaults from the configuration, like the real options', function (): void {
    config()->set('passkeys.timeout_ms', 120_000);
    config()->set('passkeys.user_verification', UserVerification::Preferred->value);
    config()->set('passkeys.resident_key', ResidentKey::Preferred->value);
    app()->forgetInstance(PasskeyConfig::class);

    $registration = $this->fake->for($this->user)->registrationOptions();
    $authentication = $this->fake->for($this->user)->authenticationOptions();

    expect($registration->timeoutMs)->toBe(120_000)
        ->and($registration->userVerification)->toBe(UserVerification::Preferred)
        ->and($registration->residentKey)->toBe(ResidentKey::Preferred)
        ->and($registration->algorithms)->toBe(app(PasskeyService::class)->for($this->user)->registrationOptions()->algorithms)
        ->and($authentication->timeoutMs)->toBe(120_000)
        ->and($authentication->userVerification)->toBe(UserVerification::Preferred)
        ->and($this->fake->authenticationOptions()->timeoutMs)->toBe(120_000);
});

it('builds its options with no relying party or origins configured', function (): void {
    config()->set('app.url', null);
    config()->set('passkeys.rp.id', null);
    config()->set('passkeys.origins', []);
    app()->forgetInstance(PasskeyConfig::class);

    expect($this->fake->for($this->user)->registrationOptions()->rpId)->toBe('localhost')
        ->and($this->fake->for($this->user)->authenticationOptions()->rpId)->toBe('localhost')
        ->and($this->fake->authenticationOptions()->rpId)->toBe('localhost');
});
