<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Passkeys\Actions\GenerateAuthenticationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\GenerateRegistrationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\VerifyAuthenticationAction;
use RoundlyConsulting\Passkeys\Actions\VerifyRegistrationAction;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
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
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Testing\VirtualAuthenticator;
use RoundlyConsulting\Passkeys\Tests\Support\AbstractOwner;
use RoundlyConsulting\Passkeys\Tests\Support\ContractOwner;
use RoundlyConsulting\Passkeys\Tests\Support\Member;
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
    $authenticator = VirtualAuthenticator::es256();
    app(VerifyRegistrationAction::class)->execute($this->user, $authenticator->register(app(GenerateRegistrationOptionsAction::class)->execute($this->user)));

    $options = app(GenerateAuthenticationOptionsAction::class)->execute();
    $passkey = app(VerifyAuthenticationAction::class)->execute($authenticator->assert($options, signCount: 7));

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
    $authenticator = VirtualAuthenticator::es256();
    $passkey = app(VerifyRegistrationAction::class)->execute($this->user, $authenticator->register(app(GenerateRegistrationOptionsAction::class)->execute($this->user)));

    $response = $authenticator->assert(app(GenerateAuthenticationOptionsAction::class)->execute());
    $resolved = app(VerifyAuthenticationAction::class)->execute($response);

    expect($response->userHandle)->toBe(Base64UrlHandle($passkey))
        ->and($resolved->authenticatable->is($this->user))->toBeTrue();
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

it('rejects a registration challenge presented to the authentication verifier', function (): void {
    $vectors = WebAuthnVectors::es256();
    registerVectors($this->user, $vectors);

    $options = app(GenerateRegistrationOptionsAction::class)->execute($this->user);
    $payload = $vectors->assertionResponse(['challenge' => $options->challenge, 'ceremonyId' => $options->ceremonyId, 'signCount' => 2]);

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
    Passkey::query()->whereKey($passkey->id)->update(['sign_count' => 10]);

    authenticate($vectors, ['signCount' => 5]);
})->throws(SignCountRegression::class);

it('flags a sign-count regression and proceeds under the flag policy', function (): void {
    Event::fake([PasskeySignCountRegressed::class]);
    $vectors = WebAuthnVectors::es256();
    $passkey = registerVectors($this->user, $vectors);
    Passkey::query()->whereKey($passkey->id)->update(['sign_count' => 10]);

    $result = authenticate($vectors, ['signCount' => 5]);

    // Flagged, allowed — and the higher counter is kept, so a clone stays visible.
    expect($result->sign_count)->toBe(10);
    Event::assertDispatched(PasskeySignCountRegressed::class);
});

it('skips the sign-count comparison for static zero counters', function (): void {
    $authenticator = VirtualAuthenticator::es256();
    // stored sign_count 0
    app(VerifyRegistrationAction::class)->execute($this->user, $authenticator->register(app(GenerateRegistrationOptionsAction::class)->execute($this->user)));

    $passkey = app(VerifyAuthenticationAction::class)->execute($authenticator->assert(app(GenerateAuthenticationOptionsAction::class)->execute(), signCount: 0));

    expect($passkey->sign_count)->toBe(0)
        ->and($passkey->last_used_at)->not->toBeNull();
});

describe('a credential whose owner no longer holds it', function (): void {
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
        $this->authenticator = VirtualAuthenticator::es256();
        $this->passkey = Passkeys::for($this->member)->register(
            $this->authenticator->register(Passkeys::for($this->member)->registrationOptions()),
        );
    });

    /**
     * The usernameless login is refused with the uniform not-found error and leaves no
     * trace: no event, and the counter and usage stamp untouched.
     */
    function expectRefusedLogin(object $test): void
    {
        Event::fake([PasskeyAuthenticated::class]);
        $before = Passkey::query()->withTrashed()->findOrFail($test->passkey->getKey());

        expect(fn () => Passkeys::authenticate($test->authenticator->assert(Passkeys::authenticationOptions())))
            ->toThrow(CredentialNotFound::class);

        $after = Passkey::query()->withTrashed()->findOrFail($test->passkey->getKey());

        expect($after->sign_count)->toBe($before->sign_count)
            ->and($after->last_used_at)->toBeNull();
        Event::assertNotDispatched(PasskeyAuthenticated::class);
    }

    it('still signs the owner in while it holds the credential', function (): void {
        $passkey = Passkeys::authenticate($this->authenticator->assert(Passkeys::authenticationOptions()));

        expect($passkey->is($this->passkey))->toBeTrue()
            ->and($passkey->authenticatable->is($this->member))->toBeTrue();
    });

    it('refuses a soft-deleted owner', function (): void {
        $this->member->delete();

        expectRefusedLogin($this);
    });

    it('refuses a hard-deleted owner', function (): void {
        $this->member->forceDelete();

        expectRefusedLogin($this);
    });

    it('refuses a new account that reuses the old owner id, minting it no handle', function (): void {
        $id = $this->member->getKey();
        $this->member->forceDelete();
        $newcomer = Member::query()->create(['id' => $id, 'name' => 'Eve', 'email' => 'eve@example.com']);

        expectRefusedLogin($this);

        expect($newcomer->refresh()->passkey_user_handle)->toBeNull();
    });

    it('refuses an owner whose stored handle has changed', function (): void {
        $this->member->forceFill(['passkey_user_handle' => Base64Url::encode(random_bytes(32))])->save();

        expectRefusedLogin($this);
    });

    it('refuses a soft-deleted owner on its own handle too', function (): void {
        $options = Passkeys::for($this->member)->authenticationOptions();
        $this->member->delete();

        expect(fn () => Passkeys::for($this->member)->authenticate($this->authenticator->assert($options)))
            ->toThrow(CredentialNotFound::class);
    });

    // A host renamed its account class or changed its morph map: old rows still name
    // the old owner type. Refused like any other miss, never a raw class-not-found Error.
    it('refuses a credential whose owner type no longer resolves', function (string $type): void {
        $this->passkey->forceFill(['authenticatable_type' => $type])->save();
        Event::fake([PasskeyAuthenticated::class]);
        $options = Passkeys::authenticationOptions();

        expect(fn () => Passkeys::authenticate($this->authenticator->assert($options)))
            ->toThrow(CredentialNotFound::class, CredentialNotFound::make()->getMessage());

        $after = Passkey::query()->findOrFail($this->passkey->getKey());

        expect($after->sign_count)->toBe($this->passkey->sign_count)
            ->and($after->last_used_at)->toBeNull()
            ->and(app(ChallengeRepository::class)->pull($options->ceremonyId))->not->toBeNull();
        Event::assertNotDispatched(PasskeyAuthenticated::class);
    })->with([
        'a renamed class' => 'App\Models\RetiredMember',
        'a morph alias no longer mapped' => 'retired-member',
        'a class that is no model' => stdClass::class,
        'an abstract model' => AbstractOwner::class,
    ]);
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
    $authenticator = VirtualAuthenticator::es256();
    Passkeys::for($owner)->register($authenticator->register(Passkeys::for($owner)->registrationOptions()));

    expect(Passkeys::authenticate($authenticator->assert(Passkeys::authenticationOptions()))->authenticatable->is($owner))->toBeTrue();

    $owner->forceFill(['opaque_handle' => Base64Url::encode(random_bytes(32))])->save();

    expect(fn () => Passkeys::authenticate($authenticator->assert(Passkeys::authenticationOptions())))
        ->toThrow(CredentialNotFound::class);
});

function Base64UrlHandle(Passkey $passkey): string
{
    return Base64Url::decode($passkey->user_handle);
}
