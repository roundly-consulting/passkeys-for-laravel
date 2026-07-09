<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Contracts\PasskeyService;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Testing\FakePasskeys;
use RoundlyConsulting\Passkeys\Tests\Support\User;

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Swap', 'email' => 'swap@example.com']);
});

function integrationRegistration(): RegistrationResponseData
{
    return new RegistrationResponseData(rawId: 'raw', clientDataJson: '{}', attestationObject: 'att');
}

function integrationAssertion(): AuthenticationResponseData
{
    return new AuthenticationResponseData(rawId: 'raw', clientDataJson: '{}', authenticatorData: 'auth', signature: 'sig');
}

it('swaps the bound service for the fake', function (): void {
    $fake = Passkeys::fake();

    expect($fake)->toBeInstanceOf(FakePasskeys::class)
        ->and(app(PasskeyService::class))->toBe($fake);
});

it('drives a register then authenticate flow through the facade with no crypto', function (): void {
    $fake = Passkeys::fake();

    $passkey = Passkeys::register($this->user, integrationRegistration(), 'Laptop');
    expect($passkey)->toBeInstanceOf(Passkey::class)->and($passkey->name)->toBe('Laptop');

    $authenticated = Passkeys::authenticate(integrationAssertion());
    expect($authenticated->is($passkey))->toBeTrue();

    $fake->assertRegisteredFor($this->user);
    $fake->assertAuthenticatedFor($this->user);
});

it('rejects a fake authentication when programmed to', function (): void {
    Passkeys::fake()->rejectAuthentication();

    expect(fn (): Passkey => Passkeys::authenticate(integrationAssertion()))
        ->toThrow(CredentialNotFound::class);
});
