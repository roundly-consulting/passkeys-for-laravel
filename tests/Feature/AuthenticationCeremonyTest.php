<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Passkeys\Actions\GenerateAuthenticationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\GenerateRegistrationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\VerifyAuthenticationAction;
use RoundlyConsulting\Passkeys\Actions\VerifyRegistrationAction;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Enums\SignCountPolicy;
use RoundlyConsulting\Passkeys\Events\PasskeyAuthenticated;
use RoundlyConsulting\Passkeys\Events\PasskeySignCountRegressed;
use RoundlyConsulting\Passkeys\Exceptions\ChallengeExpired;
use RoundlyConsulting\Passkeys\Exceptions\ChallengeMismatch;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Exceptions\OriginMismatch;
use RoundlyConsulting\Passkeys\Exceptions\RpIdMismatch;
use RoundlyConsulting\Passkeys\Exceptions\SignatureInvalid;
use RoundlyConsulting\Passkeys\Exceptions\SignCountRegression;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\Base64Url;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

function registerVectors(User $user, WebAuthnVectors $vectors): Passkey
{
    $options = app(GenerateRegistrationOptionsAction::class)->execute($user);
    $payload = $vectors->registrationResponse(['challenge' => $options->challenge, 'ceremonyId' => $options->ceremonyId]);

    return app(VerifyRegistrationAction::class)->execute($user, RegistrationResponseData::fromArray($payload));
}

/**
 * @param  array<string, mixed>  $overrides
 */
function authenticate(WebAuthnVectors $vectors, array $overrides = []): Passkey
{
    $options = app(GenerateAuthenticationOptionsAction::class)->execute();
    $payload = $vectors->assertionResponse(array_merge([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ], $overrides));

    return app(VerifyAuthenticationAction::class)->execute(AuthenticationResponseData::fromArray($payload));
}

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);
});

it('authenticates a real ES256 assertion and advances the sign counter', function (): void {
    Event::fake([PasskeyAuthenticated::class]);
    $vectors = WebAuthnVectors::es256();
    registerVectors($this->user, $vectors);

    $passkey = authenticate($vectors, ['signCount' => 7]);

    expect($passkey->sign_count)->toBe(7)
        ->and($passkey->last_used_at)->not->toBeNull();

    Event::assertDispatched(PasskeyAuthenticated::class);
});

it('authenticates a long roaming-key credential id', function (): void {
    $vectors = WebAuthnVectors::es256()->withCredentialId(random_bytes(1023));
    registerVectors($this->user, $vectors);

    $passkey = authenticate($vectors, ['signCount' => 3]);

    expect($passkey->sign_count)->toBe(3)
        ->and(strlen($passkey->credential_id))->toBeGreaterThan(1000);
});

it('authenticates a real RS256 assertion', function (): void {
    $vectors = WebAuthnVectors::rs256();
    registerVectors($this->user, $vectors);

    $passkey = authenticate($vectors, ['signCount' => 3]);

    expect($passkey->sign_count)->toBe(3);
});

it('resolves the owning user through the discoverable user handle', function (): void {
    $vectors = WebAuthnVectors::es256();
    $passkey = registerVectors($this->user, $vectors);

    $resolved = authenticate($vectors, ['signCount' => 2, 'userHandle' => Base64UrlHandle($passkey)]);

    expect($resolved->authenticatable->is($this->user))->toBeTrue();
});

it('rejects an unknown credential with a uniform not-found error', function (): void {
    authenticate(WebAuthnVectors::es256());
})->throws(CredentialNotFound::class);

it('rejects a mismatched user handle with the same not-found error', function (): void {
    $vectors = WebAuthnVectors::es256();
    registerVectors($this->user, $vectors);

    authenticate($vectors, ['signCount' => 2, 'userHandle' => 'someone-else']);
})->throws(CredentialNotFound::class);

it('rejects a tampered signature', function (): void {
    $vectors = WebAuthnVectors::es256();
    registerVectors($this->user, $vectors);

    authenticate($vectors, ['signCount' => 2, 'tamperSignature' => true]);
})->throws(SignatureInvalid::class);

it('rejects an assertion signed over different data', function (): void {
    $vectors = WebAuthnVectors::es256();
    registerVectors($this->user, $vectors);

    authenticate($vectors, ['signCount' => 2, 'tamperSignedData' => true]);
})->throws(SignatureInvalid::class);

it('rejects a replayed challenge', function (): void {
    $vectors = WebAuthnVectors::es256();
    registerVectors($this->user, $vectors);

    $options = app(GenerateAuthenticationOptionsAction::class)->execute();
    $payload = $vectors->assertionResponse(['challenge' => $options->challenge, 'ceremonyId' => $options->ceremonyId, 'signCount' => 2]);

    app(VerifyAuthenticationAction::class)->execute(AuthenticationResponseData::fromArray($payload));

    // The challenge was consumed on first use; the same ceremony id no longer resolves.
    app(VerifyAuthenticationAction::class)->execute(AuthenticationResponseData::fromArray($payload));
})->throws(ChallengeExpired::class);

it('rejects a mismatched assertion challenge', function (): void {
    $vectors = WebAuthnVectors::es256();
    registerVectors($this->user, $vectors);

    $options = app(GenerateAuthenticationOptionsAction::class)->execute();
    $payload = $vectors->assertionResponse(['challenge' => 'wrong', 'ceremonyId' => $options->ceremonyId, 'signCount' => 2]);

    app(VerifyAuthenticationAction::class)->execute(AuthenticationResponseData::fromArray($payload));
})->throws(ChallengeMismatch::class);

it('rejects an assertion from a disallowed origin', function (): void {
    $vectors = WebAuthnVectors::es256();
    registerVectors($this->user, $vectors);

    authenticate($vectors, ['signCount' => 2, 'origin' => 'https://evil.example']);
})->throws(OriginMismatch::class);

it('rejects an assertion with a mismatched rp id hash', function (): void {
    $vectors = WebAuthnVectors::es256();
    registerVectors($this->user, $vectors);

    authenticate($vectors, ['signCount' => 2, 'rpId' => 'attacker.test']);
})->throws(RpIdMismatch::class);

it('throws on a sign-count regression under the reject policy', function (): void {
    config()->set('passkeys.sign_count_policy', SignCountPolicy::Reject->value);
    app()->forgetInstance(PasskeyConfig::class);

    $vectors = WebAuthnVectors::es256();
    $passkey = registerVectors($this->user, $vectors);
    $passkey->touchUsage(10);

    authenticate($vectors, ['signCount' => 5]);
})->throws(SignCountRegression::class);

it('flags a sign-count regression and proceeds under the flag policy', function (): void {
    Event::fake([PasskeySignCountRegressed::class]);
    $vectors = WebAuthnVectors::es256();
    $passkey = registerVectors($this->user, $vectors);
    $passkey->touchUsage(10);

    $result = authenticate($vectors, ['signCount' => 5]);

    expect($result->sign_count)->toBe(5);
    Event::assertDispatched(PasskeySignCountRegressed::class);
});

it('skips the sign-count comparison for static zero counters', function (): void {
    $vectors = WebAuthnVectors::es256();
    registerVectors($this->user, $vectors); // stored sign_count 0

    $passkey = authenticate($vectors, ['signCount' => 0]);

    expect($passkey->sign_count)->toBe(0)
        ->and($passkey->last_used_at)->not->toBeNull();
});

function Base64UrlHandle(Passkey $passkey): string
{
    return Base64Url::decode($passkey->user_handle);
}
