<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationExpectation;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Exceptions\InvalidExpectation;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\Client;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

/**
 * A multi-guard host: `User` and `Client` both own passkeys through the same morph, and
 * share the key 1. The expectation is checked right after the credential is located —
 * before the challenge is consumed and before any write.
 */
function expectationEnrol(User|Client $owner, WebAuthnVectors $vectors): Passkey
{
    $options = $owner->passkeyRegistrationOptions();

    return $owner->registerPasskey(RegistrationResponseData::fromArray($vectors->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ])));
}

function expectationAssert(RequestOptionsData $options, WebAuthnVectors $vectors, ?AuthenticationExpectation $expect): Passkey
{
    return Passkeys::authenticate(AuthenticationResponseData::fromArray($vectors->assertionResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
        'signCount' => 11,
    ])), $expect);
}

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Uma', 'email' => 'uma@example.com']);
    $this->client = Client::query()->create(['name' => 'Acme', 'email' => 'acme@example.com']);
    $this->userKey = WebAuthnVectors::es256();
    $this->clientKey = WebAuthnVectors::es256();
    $this->userPasskey = expectationEnrol($this->user, $this->userKey);
    $this->clientPasskey = expectationEnrol($this->client, $this->clientKey);
});

it('runs with two owners that share the same key', function (): void {
    expect($this->user->getKey())->toBe($this->client->getKey());
});

it('refuses a credential of another owner type before the challenge is pulled', function (): void {
    $options = Passkeys::authenticationOptions();
    $expect = AuthenticationExpectation::ownerType($this->client->getMorphClass());

    expect(fn (): Passkey => expectationAssert($options, $this->userKey, $expect))
        ->toThrow(CredentialNotFound::class);

    // No write happened on the refused credential.
    expect($this->userPasskey->fresh()?->sign_count)->toBe(0)
        ->and($this->userPasskey->fresh()?->last_used_at)->toBeNull();

    // The ceremony is still live: the right owner type finishes it.
    expect(expectationAssert($options, $this->clientKey, $expect)->is($this->clientPasskey))->toBeTrue()
        ->and(app(ChallengeRepository::class)->pull($options->ceremonyId))->toBeNull();
});

it('accepts a credential of the expected owner type', function (): void {
    $options = Passkeys::authenticationOptions();

    $passkey = expectationAssert($options, $this->userKey, AuthenticationExpectation::ownerType($this->user->getMorphClass()));

    expect($passkey->is($this->userPasskey))->toBeTrue()
        ->and($passkey->sign_count)->toBe(11);
});

it('refuses another account\'s credential under an exact-owner expectation', function (): void {
    $other = User::query()->create(['name' => 'Olga', 'email' => 'olga@example.com']);
    $otherKey = WebAuthnVectors::es256();
    $otherPasskey = expectationEnrol($other, $otherKey);

    $options = Passkeys::authenticationOptions();

    expect(fn (): Passkey => expectationAssert($options, $otherKey, AuthenticationExpectation::owner($this->user)))
        ->toThrow(CredentialNotFound::class)
        ->and($otherPasskey->fresh()?->last_used_at)->toBeNull();
});

it('refuses an owner of another type even when the key is the same', function (): void {
    $options = Passkeys::authenticationOptions();

    expect(fn (): Passkey => expectationAssert($options, $this->userKey, AuthenticationExpectation::owner($this->client)))
        ->toThrow(CredentialNotFound::class);
});

it('accepts the exact expected owner on a ceremony bound to that owner', function (): void {
    // The second-factor shape: options for the known account + its exact expectation.
    $options = $this->user->passkeyAuthenticationOptions();

    $passkey = expectationAssert($options, $this->userKey, AuthenticationExpectation::owner($this->user));

    expect($passkey->is($this->userPasskey))->toBeTrue();
});

it('keeps working without an expectation', function (): void {
    expect(expectationAssert(Passkeys::authenticationOptions(), $this->clientKey, null)->is($this->clientPasskey))->toBeTrue();
});

it('refuses to build an exact-owner expectation from an unsaved owner', function (): void {
    AuthenticationExpectation::owner(new User(['name' => 'Ghost']));
})->throws(InvalidExpectation::class);
