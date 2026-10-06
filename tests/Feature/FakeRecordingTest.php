<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Passkeys\Contracts\PasskeyService;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Events\PasskeyAuthenticated;
use RoundlyConsulting\Passkeys\Events\PasskeyRegistered;
use RoundlyConsulting\Passkeys\Exceptions\CredentialAlreadyRegistered;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyAssertionFailed;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Testing\PasskeysFake;
use RoundlyConsulting\Passkeys\Testing\RecordingUserPasskeys;
use RoundlyConsulting\Passkeys\Tests\Support\User;

function recordingResponse(): RegistrationResponseData
{
    return new RegistrationResponseData(rawId: 'raw', clientDataJson: '{}', attestationObject: 'att');
}

function recordingAssertion(): AuthenticationResponseData
{
    return new AuthenticationResponseData(rawId: 'raw', clientDataJson: '{}', authenticatorData: 'auth', signature: 'sig');
}

beforeEach(function (): void {
    $this->alice = User::query()->create(['name' => 'Alice', 'email' => 'alice@example.com']);
    $this->bob = User::query()->create(['name' => 'Bob', 'email' => 'bob@example.com']);
});

it('hands out recording handles and takes over DI', function (): void {
    $fake = Passkeys::fake();

    expect(Passkeys::for($this->alice))->toBeInstanceOf(RecordingUserPasskeys::class)
        ->and(app(PasskeyService::class))->toBe($fake)
        ->and(Passkeys::attestationFormats())->toBe(['none', 'packed', 'apple']);
});

it('records a registration made through the model verb', function (): void {
    $fake = Passkeys::fake();

    $passkey = $this->alice->registerPasskey(recordingResponse(), 'Phone');

    expect($passkey->name)->toBe('Phone')
        ->and($this->alice->hasPasskeys())->toBeTrue()
        ->and($this->alice->passkeyCount())->toBe(1)
        ->and($this->alice->passkeyRegistrationOptions()->rpName)->toBe('Fake')
        ->and($this->alice->passkeyAuthenticationOptions()->rpId)->toBe('localhost');
    $fake->assertRegisteredFor($this->alice);
    expect(fn () => $fake->assertRegisteredFor($this->bob))->toThrow(PasskeyAssertionFailed::class);
});

it('holds a handle authentication to its account', function (): void {
    $fake = Passkeys::fake();
    Passkeys::for($this->alice)->register(recordingResponse());

    expect(Passkeys::for($this->alice)->authenticate(recordingAssertion())->authenticatable->is($this->alice))->toBeTrue()
        ->and(fn () => Passkeys::for($this->bob)->authenticate(recordingAssertion()))->toThrow(CredentialNotFound::class);

    $fake->assertAuthenticatedFor($this->alice);
    $fake->assertAuthenticationFailed();
    $fake->assertAuthenticationCount(2);
});

it('records renames and revocations made through the handle', function (): void {
    $fake = Passkeys::fake();
    $passkey = Passkey::factory()->forAuthenticatable($this->alice)->create(['name' => 'Old']);
    $other = Passkey::factory()->forAuthenticatable($this->alice)->create();

    Passkeys::for($this->alice)->rename($passkey->getKey(), 'New');
    Passkeys::for($this->alice)->revoke($passkey->getKey());

    expect($passkey->refresh()->name)->toBe('New')
        ->and($passkey->trashed())->toBeTrue();

    $fake->assertRenamed();
    $fake->assertRenamed($passkey);
    $fake->assertRenamed($passkey, 'New');
    $fake->assertRevoked();
    $fake->assertRevoked($passkey);

    expect(fn () => $fake->assertRenamed($passkey, 'Other'))->toThrow(PasskeyAssertionFailed::class, 'rename')
        ->and(fn () => $fake->assertRenamed($other))->toThrow(PasskeyAssertionFailed::class)
        ->and(fn () => $fake->assertRevoked($other))->toThrow(PasskeyAssertionFailed::class, 'revocation')
        ->and(fn () => $fake->assertNothingRenamed())->toThrow(PasskeyAssertionFailed::class, '1 were recorded')
        ->and(fn () => $fake->assertNothingRevoked())->toThrow(PasskeyAssertionFailed::class, '1 were recorded');
});

it('passes the negative asserts and fails the positive ones when nothing happened', function (): void {
    $fake = Passkeys::fake();

    $fake->assertNothingRenamed();
    $fake->assertNothingRevoked();
    $fake->assertNothingRegistered();

    expect(fn () => $fake->assertRenamed())->toThrow(PasskeyAssertionFailed::class)
        ->and(fn () => $fake->assertRevoked())->toThrow(PasskeyAssertionFailed::class);
});

it('refuses cross-account writes under the fake and records nothing', function (): void {
    $fake = Passkeys::fake();
    $bobs = Passkey::factory()->forAuthenticatable($this->bob)->create(['name' => 'Bob key']);

    expect(fn () => Passkeys::for($this->alice)->rename($bobs, 'Stolen'))->toThrow(CredentialNotFound::class)
        ->and(fn () => Passkeys::for($this->alice)->revoke($bobs->getKey()))->toThrow(CredentialNotFound::class);

    $fake->assertNothingRenamed();
    $fake->assertNothingRevoked();
    expect($bobs->refresh()->trashed())->toBeFalse();
});

it('refuses a revoked passkey under the fake, as the real service does', function (): void {
    $fake = Passkeys::fake();
    $passkey = Passkeys::for($this->alice)->register(recordingResponse());
    Passkeys::for($this->alice)->revoke($passkey->getKey());

    expect(fn () => Passkeys::for($this->alice)->authenticate(recordingAssertion()))->toThrow(CredentialNotFound::class)
        ->and(fn () => Passkeys::authenticate(recordingAssertion()))->toThrow(CredentialNotFound::class);

    $fake->assertAuthenticationFailed();
    $fake->assertAuthenticationCount(2);
    expect(fn () => $fake->assertAuthenticated())->toThrow(PasskeyAssertionFailed::class);
});

it('refuses a trashed or unsaved authenticatesAs() passkey under the fake', function (): void {
    $fake = Passkeys::fake();
    $trashed = Passkey::factory()->forAuthenticatable($this->alice)->create();
    $trashed->delete();

    $fake->authenticatesAs($trashed);
    expect(fn () => Passkeys::authenticate(recordingAssertion()))->toThrow(CredentialNotFound::class);

    $fake->authenticatesAs(Passkey::factory()->forAuthenticatable($this->alice)->make());
    expect(fn () => Passkeys::authenticate(recordingAssertion()))->toThrow(CredentialNotFound::class);

    $fake->assertAuthenticationFailed();
    $fake->assertAuthenticationCount(2);
    expect(fn () => $fake->assertAuthenticated())->toThrow(PasskeyAssertionFailed::class);
});

it('stamps usage on a fake sign-in and none on a fake registration, as the real ceremonies do', function (): void {
    Carbon::setTestNow('2026-10-06 12:00:00');
    Passkeys::fake();

    $passkey = Passkeys::for($this->alice)->register(recordingResponse());

    expect($passkey->last_used_at)->toBeNull()
        ->and($passkey->fresh()?->last_used_at)->toBeNull();

    Carbon::setTestNow('2026-10-06 12:05:00');
    $signedIn = Passkeys::for($this->alice)->authenticate(recordingAssertion());

    expect($signedIn->last_used_at?->toDateTimeString())->toBe('2026-10-06 12:05:00')
        ->and($passkey->fresh()?->last_used_at?->toDateTimeString())->toBe('2026-10-06 12:05:00');

    Carbon::setTestNow();
});

it('fires the ceremony events from a fake register and authenticate, as the real ceremonies do', function (): void {
    Event::fake([PasskeyRegistered::class, PasskeyAuthenticated::class]);
    Passkeys::fake();

    $passkey = Passkeys::for($this->alice)->register(recordingResponse());
    $signedIn = Passkeys::for($this->alice)->authenticate(recordingAssertion());

    Event::assertDispatchedTimes(PasskeyRegistered::class, 1);
    Event::assertDispatched(PasskeyRegistered::class, fn (PasskeyRegistered $event): bool => $event->passkey->is($passkey));
    Event::assertDispatchedTimes(PasskeyAuthenticated::class, 1);
    Event::assertDispatched(PasskeyAuthenticated::class, fn (PasskeyAuthenticated $event): bool => $event->passkey->is($signedIn));
});

it('fires no ceremony event when the fake is programmed to fail', function (): void {
    Event::fake([PasskeyRegistered::class, PasskeyAuthenticated::class]);
    Passkeys::fake()->failRegistrationWith(CredentialAlreadyRegistered::make())->rejectAuthentication();

    expect(fn () => Passkeys::for($this->alice)->register(recordingResponse()))->toThrow(CredentialAlreadyRegistered::class)
        ->and(fn () => Passkeys::authenticate(recordingAssertion()))->toThrow(CredentialNotFound::class);

    Event::assertNotDispatched(PasskeyRegistered::class);
    Event::assertNotDispatched(PasskeyAuthenticated::class);
});

it('builds the fake from the container', function (): void {
    expect(app(PasskeysFake::class)->for($this->alice)->count())->toBe(0);
});
