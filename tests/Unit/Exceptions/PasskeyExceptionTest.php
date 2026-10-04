<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Exceptions\ChallengeExpired;
use RoundlyConsulting\Passkeys\Exceptions\ChallengeMismatch;
use RoundlyConsulting\Passkeys\Exceptions\CredentialAlreadyRegistered;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAuthenticatorData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidConfiguration;
use RoundlyConsulting\Passkeys\Exceptions\InvalidCoseKey;
use RoundlyConsulting\Passkeys\Exceptions\MalformedCbor;
use RoundlyConsulting\Passkeys\Exceptions\OriginMismatch;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Exceptions\RpIdMismatch;
use RoundlyConsulting\Passkeys\Exceptions\SignatureInvalid;
use RoundlyConsulting\Passkeys\Exceptions\SignCountRegression;
use RoundlyConsulting\Passkeys\Exceptions\UnsupportedAlgorithm;
use RoundlyConsulting\Passkeys\Exceptions\UserVerificationRequired;

it('resolves translated, non-empty messages for the simple factories', function (callable $factory): void {
    $exception = $factory();

    expect($exception)->toBeInstanceOf(PasskeyException::class)
        ->and($exception->getMessage())->toBeString()->not->toBeEmpty();
})->with([
    'challenge expired' => [fn () => ChallengeExpired::make()],
    'challenge mismatch' => [fn () => ChallengeMismatch::make()],
    'credential already registered' => [fn () => CredentialAlreadyRegistered::make()],
    'credential not found' => [fn () => CredentialNotFound::make()],
    'invalid authenticator data' => [fn () => InvalidAuthenticatorData::make()],
    'user presence missing' => [fn () => InvalidAuthenticatorData::userPresenceMissing()],
    'backup state inconsistent' => [fn () => InvalidAuthenticatorData::backupStateInconsistent()],
    'attested data missing' => [fn () => InvalidAuthenticatorData::attestedDataMissing()],
    'invalid client data' => [fn () => InvalidClientData::malformed()],
    'origin mismatch' => [fn () => OriginMismatch::make()],
    'cross origin' => [fn () => OriginMismatch::crossOrigin()],
    'rp id mismatch' => [fn () => RpIdMismatch::make()],
    'signature invalid' => [fn () => SignatureInvalid::make()],
    'user verification required' => [fn () => UserVerificationRequired::make()],
    'missing rp id' => [fn () => InvalidConfiguration::missingRpId()],
    'empty origins' => [fn () => InvalidConfiguration::emptyOrigins()],
]);

it('includes context in the parameterised factories', function (): void {
    expect(InvalidClientData::wrongType('webauthn.create')->getMessage())->toContain('webauthn.create');
    expect(UnsupportedAlgorithm::forId(-999)->getMessage())->toContain('-999');
    expect(InvalidCoseKey::make('bad curve')->getMessage())->toContain('bad curve');
    expect(MalformedCbor::make('truncated')->getMessage())->toContain('truncated');
    expect(SignCountRegression::make(10, 5)->getMessage())->toContain('5 <= 10');
});

it('is throwable and catchable as the package base type', function (): void {
    expect(fn () => throw RpIdMismatch::make())->toThrow(PasskeyException::class);
});

/**
 * The package's own message fragments of one group, per language.
 *
 * @return array<string, string>
 */
function errorFragments(string $locale, string $group): array
{
    /** @var array<string, array<string, string>|string> $lines */
    $lines = require __DIR__.'/../../../resources/lang/'.$locale.'/errors.php';

    $fragments = $lines[$group];

    expect($fragments)->toBeArray()->not->toBeEmpty();

    /** @var array<string, string> $fragments */
    return $fragments;
}

it('words every configuration expectation in the app locale', function (): void {
    foreach (errorFragments('en', 'config_expectations') as $code => $english) {
        $slovak = errorFragments('sk', 'config_expectations')[$code];

        app()->setLocale('sk');

        expect(InvalidConfiguration::invalidValue('origins', $code, 1)->getMessage())
            ->toBe("Nastavenie passkeys.origins musí byť {$slovak}; nastavená hodnota je int.");

        app()->setLocale('en');

        expect(InvalidConfiguration::invalidValue('origins', $code, 1)->getMessage())
            ->toBe("passkeys.origins must be {$english}; int was configured.");
    }
});

it('keeps a caller\'s own expectation wording as is', function (string $expected): void {
    expect(InvalidConfiguration::invalidValue('custom', $expected, 'x')->getMessage())
        ->toBe("passkeys.custom must be {$expected}; \"x\" was configured.");
})->with([
    'prose' => ['a positive number'],
    'a code of another group' => ['errors::string'],
    'an unknown code' => ['positive_number'],
]);
