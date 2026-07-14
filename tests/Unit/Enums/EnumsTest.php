<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\AttestationTrust;
use RoundlyConsulting\Passkeys\Enums\AuthenticatorAttachment;
use RoundlyConsulting\Passkeys\Enums\CeremonyType;
use RoundlyConsulting\Passkeys\Enums\ResidentKey;
use RoundlyConsulting\Passkeys\Enums\SignCountPolicy;
use RoundlyConsulting\Passkeys\Enums\UserVerification;

// The COSE algorithm registry now lives in crypto-for-laravel; the identifiers
// this relying party accepts are asserted against it in PasskeyConfigTest.

it('adopts the shared enums-for-laravel helpers on every enum', function (string $enum): void {
    /** @var class-string<UserVerification> $enum */
    expect($enum::values()->all())->not->toBeEmpty()
        ->and($enum::options())->not->toBeEmpty()
        ->and($enum::count())->toBeGreaterThan(0);
})->with([
    UserVerification::class,
    AttestationConveyance::class,
    AttestationTrust::class,
    SignCountPolicy::class,
    ResidentKey::class,
    AuthenticatorAttachment::class,
    CeremonyType::class,
]);

it('exposes the ceremony-type cases', function (): void {
    expect(CeremonyType::from('registration'))->toBe(CeremonyType::Registration)
        ->and(CeremonyType::from('authentication'))->toBe(CeremonyType::Authentication);
});

it('exposes resident-key and authenticator-attachment cases', function (): void {
    expect(ResidentKey::from('required'))->toBe(ResidentKey::Required)
        ->and(ResidentKey::from('discouraged'))->toBe(ResidentKey::Discouraged)
        ->and(AuthenticatorAttachment::from('platform'))->toBe(AuthenticatorAttachment::Platform)
        ->and(AuthenticatorAttachment::from('cross-platform'))->toBe(AuthenticatorAttachment::CrossPlatform);
});

it('resolves user-verification cases from their backed value', function (): void {
    expect(UserVerification::from('required'))->toBe(UserVerification::Required)
        ->and(UserVerification::tryFrom('preferred'))->toBe(UserVerification::Preferred);
});

it('exposes attestation-conveyance and trust cases', function (): void {
    expect(AttestationConveyance::from('none'))->toBe(AttestationConveyance::None)
        ->and(AttestationTrust::from('ignore'))->toBe(AttestationTrust::Ignore)
        ->and(AttestationTrust::from('self'))->toBe(AttestationTrust::SelfAttested)
        ->and(SignCountPolicy::from('flag'))->toBe(SignCountPolicy::Flag);
});

it('produces a readable label through the shared helper', function (): void {
    expect(UserVerification::Required->label())->toBeString()->not->toBeEmpty();
});
