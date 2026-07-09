<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Exceptions\CredentialAlreadyRegistered;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Managed', 'email' => 'managed@example.com']);
});

function registerNamed(User $user, WebAuthnVectors $vectors, ?string $name): Passkey
{
    $options = Passkeys::registrationOptions($user);
    $payload = $vectors->registrationResponse(['challenge' => $options->challenge, 'ceremonyId' => $options->ceremonyId]);

    return Passkeys::register($user, RegistrationResponseData::fromArray($payload), $name);
}

function assertLogin(User $user, WebAuthnVectors $vectors): Passkey
{
    $options = Passkeys::authenticationOptions();
    $payload = $vectors->assertionResponse(['challenge' => $options->challenge, 'ceremonyId' => $options->ceremonyId, 'signCount' => 5]);

    return Passkeys::authenticate(AuthenticationResponseData::fromArray($payload));
}

it('stores a friendly name supplied at registration', function (): void {
    $passkey = registerNamed($this->user, WebAuthnVectors::es256(), 'MacBook Touch ID');

    expect($passkey->name)->toBe('MacBook Touch ID');
});

it('leaves the name null when none is supplied', function (): void {
    $passkey = registerNamed($this->user, WebAuthnVectors::es256(), null);

    expect($passkey->name)->toBeNull();
});

it('renames a stored credential', function (): void {
    $passkey = registerNamed($this->user, WebAuthnVectors::es256(), 'Old');

    Passkeys::rename($passkey, 'Work laptop');

    expect($passkey->refresh()->name)->toBe('Work laptop');
});

it('revokes a credential so it can no longer authenticate', function (): void {
    $vectors = WebAuthnVectors::es256();
    $passkey = registerNamed($this->user, $vectors, 'Lost key');

    Passkeys::revoke($passkey);

    expect($passkey->refresh()->trashed())->toBeTrue();
    expect(fn () => assertLogin($this->user, $vectors))->toThrow(CredentialNotFound::class);
});

it('still blocks re-registering a revoked credential id', function (): void {
    $vectors = WebAuthnVectors::es256();
    $passkey = registerNamed($this->user, $vectors, null);
    Passkeys::revoke($passkey);

    expect(fn () => registerNamed($this->user, $vectors, null))
        ->toThrow(CredentialAlreadyRegistered::class);
});
