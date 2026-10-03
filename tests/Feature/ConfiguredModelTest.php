<?php

declare(strict_types=1);

use RoundlyConsulting\PackageToolkit\Exceptions\InvalidConfigurationException;
use RoundlyConsulting\Passkeys\Actions\GenerateAuthenticationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\GenerateRegistrationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\VerifyAuthenticationAction;
use RoundlyConsulting\Passkeys\Actions\VerifyRegistrationAction;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\PasskeyModel;
use RoundlyConsulting\Passkeys\Tests\Support\CustomPasskey;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

/**
 * `passkeys.model` is documented as the credential-model seam. Every call site must resolve
 * it — a ceremony that hard-codes the packaged class hands the host back the wrong model and
 * never fires the model events the host's own class declares.
 */
beforeEach(function (): void {
    config()->set('passkeys.model', CustomPasskey::class);

    CustomPasskey::resetCreationCount();

    $this->user = User::query()->create(['name' => 'Ada', 'email' => 'ada@example.com']);
});

it('resolves the configured model', function (): void {
    expect(PasskeyModel::class())->toBe(CustomPasskey::class)
        ->and(PasskeyModel::query()->getModel())->toBeInstanceOf(CustomPasskey::class);
});

it('falls back to the packaged model when none is configured', function (): void {
    config()->set('passkeys.model', null);

    expect(PasskeyModel::class())->toBe(Passkey::class);
});

it('refuses a foreign model instead of falling back to the packaged one', function (): void {
    // The toolkit refuses any class that is not the packaged model or a subclass of it.
    config()->set('passkeys.model', User::class);

    expect(fn (): string => PasskeyModel::class())->toThrow(
        InvalidConfigurationException::class,
        'Configuration value [passkeys.model] must be a class-string of ['.Passkey::class.'], ['.User::class.'] given.',
    );
});

it('refuses a configured class that is not a model at all', function (): void {
    config()->set('passkeys.model', 'Acme\\NotAModel');

    PasskeyModel::class();
})->throws(InvalidConfigurationException::class);

it('points the user relation at the configured model', function (): void {
    expect($this->user->passkeys()->getModel())->toBeInstanceOf(CustomPasskey::class);
});

it('persists a registration as the configured model and fires its events', function (): void {
    $options = app(GenerateRegistrationOptionsAction::class)->execute($this->user);

    $payload = WebAuthnVectors::es256()->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ]);

    $passkey = app(VerifyRegistrationAction::class)->execute($this->user, RegistrationResponseData::fromArray($payload));

    expect($passkey)->toBeInstanceOf(CustomPasskey::class)
        // The `created` event of the CONFIGURED class fired — the whole point of the seam.
        ->and(CustomPasskey::creationCount())->toBe(1);
});

it('returns the configured model from an authentication ceremony', function (): void {
    $vectors = WebAuthnVectors::es256();

    $registration = app(GenerateRegistrationOptionsAction::class)->execute($this->user);
    app(VerifyRegistrationAction::class)->execute($this->user, RegistrationResponseData::fromArray(
        $vectors->registrationResponse([
            'challenge' => $registration->challenge,
            'ceremonyId' => $registration->ceremonyId,
        ]),
    ));

    $options = app(GenerateAuthenticationOptionsAction::class)->execute();
    $assertion = $vectors->assertionResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ]);

    $passkey = app(VerifyAuthenticationAction::class)->execute(AuthenticationResponseData::fromArray($assertion));

    expect($passkey)->toBeInstanceOf(CustomPasskey::class)
        ->and($passkey->revoked())->toBeFalse();
});

it('builds the configured model from the factory', function (): void {
    expect(Passkey::factory()->es256()->make())->toBeInstanceOf(CustomPasskey::class);
});
