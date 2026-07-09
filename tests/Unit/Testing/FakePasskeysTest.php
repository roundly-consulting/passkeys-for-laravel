<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyAssertionFailed;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Testing\FakePasskeys;
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
    $this->fake = new FakePasskeys;
});

it('returns canned option DTOs with no crypto', function (): void {
    expect($this->fake->registrationOptions($this->user))->toBeInstanceOf(CreationOptionsData::class)
        ->and($this->fake->authenticationOptions())->toBeInstanceOf(RequestOptionsData::class);
});

it('persists a passkey on register and records the call', function (): void {
    $passkey = $this->fake->register($this->user, fakeRegistrationResponse(), 'My Phone');

    expect($passkey->exists)->toBeTrue()
        ->and($passkey->name)->toBe('My Phone')
        ->and($passkey->authenticatable->is($this->user))->toBeTrue();

    $this->fake->assertRegistered();
    $this->fake->assertRegisteredFor($this->user);
    $this->fake->assertRegistrationCount(1);
});

it('throws the programmed exception on register', function (): void {
    $this->fake->failRegistrationWith(CredentialNotFound::make());

    expect(fn (): Passkey => $this->fake->register($this->user, fakeRegistrationResponse()))
        ->toThrow(CredentialNotFound::class);

    $this->fake->assertNothingRegistered();
});

it('accepts registration again after being reset', function (): void {
    $this->fake->failRegistrationWith(CredentialNotFound::make())->acceptRegistration();

    expect($this->fake->register($this->user, fakeRegistrationResponse())->exists)->toBeTrue();
});

it('authenticates as the last registered credential by default', function (): void {
    $registered = $this->fake->register($this->user, fakeRegistrationResponse());

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
    $this->fake->register($this->user, fakeRegistrationResponse());
    $this->fake->rejectAuthentication()->acceptAuthentication();

    expect($this->fake->authenticate(fakeAssertionResponse())->exists)->toBeTrue();
});

it('rejects authentication when programmed to', function (): void {
    $this->fake->rejectAuthentication();

    expect(fn (): Passkey => $this->fake->authenticate(fakeAssertionResponse()))
        ->toThrow(CredentialNotFound::class);

    $this->fake->assertAuthenticationFailed();
});

it('renames and revokes a stored credential', function (): void {
    $passkey = Passkey::factory()->forAuthenticatable($this->user)->create();

    $this->fake->rename($passkey, 'Renamed');
    expect($passkey->refresh()->name)->toBe('Renamed');

    $this->fake->revoke($passkey);
    expect($passkey->refresh()->trashed())->toBeTrue();
});

it('fails assertRegistered when nothing registered', function (): void {
    expect(fn () => $this->fake->assertRegistered())->toThrow(PasskeyAssertionFailed::class);
    expect(fn () => $this->fake->assertRegisteredFor($this->user))->toThrow(PasskeyAssertionFailed::class);
});

it('fails assertNothingRegistered when a registration happened', function (): void {
    $this->fake->register($this->user, fakeRegistrationResponse());

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
    $this->fake->register($this->user, fakeRegistrationResponse());

    expect(fn () => $this->fake->assertRegisteredFor($other))->toThrow(PasskeyAssertionFailed::class);
});
