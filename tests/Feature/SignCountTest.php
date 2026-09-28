<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Passkeys\Actions\GenerateAuthenticationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\GenerateRegistrationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\VerifyAuthenticationAction;
use RoundlyConsulting\Passkeys\Actions\VerifyRegistrationAction;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Enums\SignCountPolicy;
use RoundlyConsulting\Passkeys\Events\PasskeySignCountRegressed;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Exceptions\SignCountRegression;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

/*
 * WebAuthn §7.2 step 21: the stored counter only ever moves FORWARD. A regression
 * is a clone signal — flagging it must not write the clone's counter back, or
 * every later assertion from the clone goes quiet.
 */

function enrolCounter(User $user, WebAuthnVectors $vectors, int $signCount): Passkey
{
    $options = app(GenerateRegistrationOptionsAction::class)->execute($user);
    $payload = $vectors->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
        'signCount' => $signCount,
    ]);

    return app(VerifyRegistrationAction::class)->execute($user, RegistrationResponseData::fromArray($payload));
}

function assertCounter(Passkey $passkey, WebAuthnVectors $vectors, int $signCount): Passkey
{
    $options = app(GenerateAuthenticationOptionsAction::class)->execute();
    $payload = $vectors->assertionResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
        'signCount' => $signCount,
        'userHandle' => Base64Url::decode($passkey->user_handle),
    ]);

    return app(VerifyAuthenticationAction::class)->execute(AuthenticationResponseData::fromArray($payload));
}

/** Simulate a concurrent assertion committing between our read and our write. */
function interleave(Closure $write): void
{
    $fired = false;

    Passkey::retrieved(static function () use (&$fired, $write): void {
        if (! $fired) {
            $fired = true;
            $write();
        }
    });
}

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);
    $this->vectors = WebAuthnVectors::es256();
});

it('never lowers the stored counter under the flag policy, so a clone keeps being flagged', function (): void {
    Event::fake([PasskeySignCountRegressed::class]);
    $passkey = enrolCounter($this->user, $this->vectors, 50);

    foreach ([0, 0, 0] as $cloneCounter) {
        expect(assertCounter($passkey, $this->vectors, $cloneCounter)->sign_count)->toBe(50);
    }

    expect($passkey->fresh()?->sign_count)->toBe(50)
        ->and($passkey->fresh()?->last_used_at)->not->toBeNull();
    Event::assertDispatchedTimes(PasskeySignCountRegressed::class, 3);
});

it('keeps the higher counter when a non-zero counter regresses under the flag policy', function (): void {
    Event::fake([PasskeySignCountRegressed::class]);
    $passkey = enrolCounter($this->user, $this->vectors, 10);

    expect(assertCounter($passkey, $this->vectors, 5)->sign_count)->toBe(10);

    Event::assertDispatched(
        PasskeySignCountRegressed::class,
        static fn (PasskeySignCountRegressed $event): bool => $event->stored === 10 && $event->received === 5,
    );
});

it('advances the counter when it moves forward', function (): void {
    Event::fake([PasskeySignCountRegressed::class]);
    $passkey = enrolCounter($this->user, $this->vectors, 10);

    expect(assertCounter($passkey, $this->vectors, 11)->sign_count)->toBe(11)
        ->and($passkey->fresh()?->sign_count)->toBe(11);
    Event::assertNotDispatched(PasskeySignCountRegressed::class);
});

it('lets the database decide when a concurrent assertion advanced the counter first (flag)', function (): void {
    Event::fake([PasskeySignCountRegressed::class]);
    $passkey = enrolCounter($this->user, $this->vectors, 5);

    // Our assertion reads 5 and receives 7 — but another one commits 10 in between.
    interleave(static fn () => Passkey::query()->whereKey($passkey->id)->update(['sign_count' => 10]));

    $result = assertCounter($passkey, $this->vectors, 7);

    expect($result->sign_count)->toBe(10)
        ->and($passkey->fresh()?->sign_count)->toBe(10);
    Event::assertDispatched(
        PasskeySignCountRegressed::class,
        static fn (PasskeySignCountRegressed $event): bool => $event->stored === 10 && $event->received === 7,
    );
});

it('lets the database decide when a concurrent assertion advanced the counter first (reject)', function (): void {
    config()->set('passkeys.sign_count_policy', SignCountPolicy::Reject->value);
    app()->forgetInstance(PasskeyConfig::class);
    $passkey = enrolCounter($this->user, $this->vectors, 5);

    interleave(static fn () => Passkey::query()->whereKey($passkey->id)->update(['sign_count' => 10]));

    expect(fn () => assertCounter($passkey, $this->vectors, 7))->toThrow(SignCountRegression::class, '7 <= 10');
    expect($passkey->fresh()?->sign_count)->toBe(10);
});

it('refuses an assertion whose credential was revoked while it was being verified', function (): void {
    $passkey = enrolCounter($this->user, $this->vectors, 5);

    interleave(static fn () => Passkey::query()->whereKey($passkey->id)->delete());

    assertCounter($passkey, $this->vectors, 7);
})->throws(CredentialNotFound::class);

it('treats a static zero counter as counterless only while the stored counter is zero', function (): void {
    Event::fake([PasskeySignCountRegressed::class]);
    $passkey = enrolCounter($this->user, $this->vectors, 0);

    expect(assertCounter($passkey, $this->vectors, 0)->sign_count)->toBe(0);
    Event::assertNotDispatched(PasskeySignCountRegressed::class);

    // A concurrent assertion moved it to 3: a later 0 is now a regression.
    interleave(static fn () => Passkey::query()->whereKey($passkey->id)->update(['sign_count' => 3]));

    expect(assertCounter($passkey, $this->vectors, 0)->sign_count)->toBe(3);
    Event::assertDispatchedTimes(PasskeySignCountRegressed::class, 1);
});
