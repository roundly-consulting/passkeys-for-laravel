<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationOptionsOverrides;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Events\PasskeySignCountRegressed;
use RoundlyConsulting\Passkeys\Exceptions\OriginMismatch;
use RoundlyConsulting\Passkeys\Exceptions\RpIdMismatch;
use RoundlyConsulting\Passkeys\Exceptions\UserVerificationRequired;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Testing\VirtualAuthenticator;
use RoundlyConsulting\Passkeys\Tests\Support\User;

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Vera', 'email' => 'vera@example.com']);
});

it('registers and authenticates through the real verifier', function (): void {
    $authenticator = VirtualAuthenticator::es256();

    $passkey = $this->user->registerPasskey($authenticator->register($this->user->passkeyRegistrationOptions()));
    $authenticated = Passkeys::authenticate($authenticator->assert($this->user->passkeyAuthenticationOptions()));

    expect($passkey->credential_id)->toBe($authenticator->credentialId())
        ->and($passkey->attestation_format)->toBe('none')
        ->and($passkey->aaguid)->toBeNull()
        ->and($passkey->transports)->toBe(['internal'])
        ->and($authenticated->is($passkey))->toBeTrue();
});

it('advances the sign counter by one per assertion', function (): void {
    $authenticator = VirtualAuthenticator::es256();
    $this->user->registerPasskey($authenticator->register($this->user->passkeyRegistrationOptions()));

    $first = Passkeys::authenticate($authenticator->assert(Passkeys::authenticationOptions()));
    expect($first->sign_count)->toBe(1);

    $second = Passkeys::authenticate($authenticator->assert(Passkeys::authenticationOptions()));
    expect($second->sign_count)->toBe(2);
});

it('sends an explicit counter, e.g. to simulate a cloned authenticator', function (): void {
    Event::fake([PasskeySignCountRegressed::class]);
    $authenticator = VirtualAuthenticator::es256();
    $this->user->registerPasskey($authenticator->register($this->user->passkeyRegistrationOptions()));

    Passkeys::authenticate($authenticator->assert(Passkeys::authenticationOptions(), signCount: 10));
    $regressed = Passkeys::authenticate($authenticator->assert(Passkeys::authenticationOptions(), signCount: 4));

    expect($regressed->sign_count)->toBe(4);
    Event::assertDispatched(PasskeySignCountRegressed::class);
});

it('fails a presence-only assertion when verification is required', function (): void {
    $authenticator = VirtualAuthenticator::es256();
    $this->user->registerPasskey($authenticator->register($this->user->passkeyRegistrationOptions()));

    Passkeys::authenticate($authenticator->assert(
        Passkeys::for($this->user)->authenticationOptions(new AuthenticationOptionsOverrides(userVerification: UserVerification::Required)),
        userVerified: false,
    ));
})->throws(UserVerificationRequired::class);

it('passes a presence-only assertion when verification is discouraged', function (): void {
    $authenticator = VirtualAuthenticator::es256();
    $this->user->registerPasskey($authenticator->register($this->user->passkeyRegistrationOptions()));

    $passkey = Passkeys::authenticate($authenticator->assert(
        Passkeys::authenticationOptions(overrides: new AuthenticationOptionsOverrides(userVerification: UserVerification::Discouraged)),
        userVerified: false,
    ));

    expect($passkey->sign_count)->toBe(1);
});

it('returns the account handle from a resident credential for a discoverable login', function (): void {
    $authenticator = VirtualAuthenticator::es256();
    $this->user->registerPasskey($authenticator->register($this->user->passkeyRegistrationOptions()));

    $response = $authenticator->assert(Passkeys::authenticationOptions());

    expect($response->userHandle)->not->toBeNull()
        ->and(Passkeys::authenticate($response)->authenticatable->is($this->user))->toBeTrue();
});

it('omits the handle for a non-resident credential, as browsers do', function (): void {
    $authenticator = VirtualAuthenticator::es256();
    $this->user->registerPasskey($authenticator->register($this->user->passkeyRegistrationOptions(), residentKey: false));

    $response = $authenticator->assert($this->user->passkeyAuthenticationOptions());

    expect($response->userHandle)->toBeNull()
        ->and(Passkeys::authenticate($response)->authenticatable->is($this->user))->toBeTrue();
});

it('signs for an explicit relying party id', function (): void {
    $authenticator = VirtualAuthenticator::es256(rpId: 'attacker.test');

    $this->user->registerPasskey($authenticator->register($this->user->passkeyRegistrationOptions()));
})->throws(RpIdMismatch::class);

it('reports an explicit origin in the client data', function (): void {
    $authenticator = VirtualAuthenticator::es256(origin: 'https://evil.example');

    $this->user->registerPasskey($authenticator->register($this->user->passkeyRegistrationOptions()));
})->throws(OriginMismatch::class);

it('mints a distinct credential per instance', function (): void {
    expect(VirtualAuthenticator::es256()->credentialId())->not->toBe(VirtualAuthenticator::es256()->credentialId());
});
