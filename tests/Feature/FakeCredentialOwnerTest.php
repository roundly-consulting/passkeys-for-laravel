<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Events\PasskeyAuthenticated;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyAssertionFailed;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Testing\PasskeysFake;
use RoundlyConsulting\Passkeys\Tests\Support\ContractOwner;
use RoundlyConsulting\Passkeys\Tests\Support\Member;
use RoundlyConsulting\Passkeys\Tests\Support\User;

/*
 * Under `Passkeys::fake()`, a passkey whose owner no longer holds it is refused exactly
 * as the real verifier refuses it (AuthenticationCeremonyTest › a credential whose owner
 * no longer holds it): deleted, soft-deleted, or holding another handle.
 */

function ownerParityRegistration(): RegistrationResponseData
{
    return new RegistrationResponseData(rawId: 'raw', clientDataJson: '{}', attestationObject: 'att');
}

function ownerParityAssertion(): AuthenticationResponseData
{
    return new AuthenticationResponseData(rawId: 'raw', clientDataJson: '{}', authenticatorData: 'auth', signature: 'sig');
}

dataset('fake passkey sources', [
    'handed to authenticatesAs()' => [function (Member $member, PasskeysFake $fake): Passkey {
        $passkey = Passkey::factory()->es256()->forAuthenticatable($member)->create();
        $fake->authenticatesAs($passkey);

        return $passkey;
    }],
    'the last fake-registered one' => [fn (Member $member): Passkey => Passkeys::for($member)->register(ownerParityRegistration())],
]);

dataset('owners that no longer hold the passkey', [
    'hard-deleted' => [fn (Member $member): ?bool => $member->forceDelete()],
    'soft-deleted' => [fn (Member $member): ?bool => $member->delete()],
    'holding another handle' => [fn (Member $member): bool => $member->forceFill(['passkey_user_handle' => Base64Url::encode(random_bytes(32))])->save()],
]);

beforeEach(function (): void {
    Schema::create('members', function (Blueprint $table): void {
        $table->id();
        $table->string('name')->nullable();
        $table->string('email')->nullable();
        $table->passkeyUserHandle();
        $table->timestamps();
        $table->softDeletes();
    });

    $this->member = Member::query()->create(['name' => 'Ada', 'email' => 'ada@example.com']);
});

it('refuses a passkey whose owner no longer holds it, as the real verifier does', function (Closure $source, Closure $owner): void {
    $fake = Passkeys::fake();
    $passkey = $source($this->member, $fake);
    $usedAt = $passkey->fresh()?->last_used_at?->toDateTimeString();
    $owner($this->member);
    Event::fake([PasskeyAuthenticated::class]);

    expect(fn (): Passkey => Passkeys::authenticate(ownerParityAssertion()))->toThrow(CredentialNotFound::class);

    $fake->assertAuthenticationFailed();
    $fake->assertAuthenticationCount(1);
    expect(fn () => $fake->assertAuthenticated())->toThrow(PasskeyAssertionFailed::class)
        ->and($passkey->fresh()?->last_used_at?->toDateTimeString())->toBe($usedAt);
    Event::assertNotDispatched(PasskeyAuthenticated::class);
})->with('fake passkey sources')->with('owners that no longer hold the passkey');

it('still signs in a passkey its owner holds', function (Closure $source): void {
    $fake = Passkeys::fake();
    $passkey = $source($this->member, $fake);

    expect(Passkeys::authenticate(ownerParityAssertion())->is($passkey))->toBeTrue();

    $fake->assertAuthenticatedFor($this->member);
})->with('fake passkey sources');

it('refuses a soft-deleted owner on its own handle too', function (): void {
    $fake = Passkeys::fake();
    Passkeys::for($this->member)->register(ownerParityRegistration());
    $this->member->delete();

    expect(fn (): Passkey => Passkeys::for($this->member)->authenticate(ownerParityAssertion()))
        ->toThrow(CredentialNotFound::class);

    $fake->assertAuthenticationFailed();
});

it('asks a custom HasPasskeys owner for its handle through the contract', function (): void {
    Schema::create('contract_owners', function (Blueprint $table): void {
        $table->id();
        $table->string('name')->nullable();
        $table->string('email')->nullable();
        $table->string('opaque_handle')->nullable();
        $table->timestamps();
    });

    $owner = ContractOwner::query()->create([
        'name' => 'Lin',
        'email' => 'lin@example.com',
        'opaque_handle' => Base64Url::encode(random_bytes(32)),
    ]);
    $passkey = Passkey::factory()->es256()->forAuthenticatable($owner)->create();
    $fake = Passkeys::fake()->authenticatesAs($passkey);

    expect(Passkeys::authenticate(ownerParityAssertion())->is($passkey))->toBeTrue();

    $owner->forceFill(['opaque_handle' => Base64Url::encode(random_bytes(32))])->save();

    expect(fn (): Passkey => Passkeys::authenticate(ownerParityAssertion()))->toThrow(CredentialNotFound::class);
    $fake->assertAuthenticationFailed();
});

it('signs in with a passkey seeded for an account, as the testing docs show', function (): void {
    $user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);

    $passkey = Passkey::factory()->es256()->forAuthenticatable($user)->create();
    $fake = Passkeys::fake()->authenticatesAs($passkey);

    expect(Passkeys::authenticate(ownerParityAssertion())->is($passkey))->toBeTrue();
    $fake->assertAuthenticatedFor($user);
});

it('refuses a factory passkey with no real owner cleanly, never with a raw error', function (): void {
    // The factory's default owner is the morph type `user` with a random id: no class,
    // no account.
    $fake = Passkeys::fake()->authenticatesAs(Passkey::factory()->es256()->create());

    expect(fn (): Passkey => Passkeys::authenticate(ownerParityAssertion()))->toThrow(CredentialNotFound::class);

    $fake->assertAuthenticationFailed();
    $fake->assertAuthenticationCount(1);
});

it('exempts only the passkey it invents when nothing is seeded', function (): void {
    $fake = Passkeys::fake();

    // "Any valid credential": invented, so its placeholder owner is not checked.
    $invented = Passkeys::authenticate(ownerParityAssertion());

    expect($invented->exists)->toBeTrue();

    // The same passkey handed back explicitly is checked like any other.
    $fake->authenticatesAs($invented);

    expect(fn (): Passkey => Passkeys::authenticate(ownerParityAssertion()))->toThrow(CredentialNotFound::class);

    $fake->assertAuthenticationCount(2);
    $fake->assertAuthenticated();
    $fake->assertAuthenticationFailed();
});
