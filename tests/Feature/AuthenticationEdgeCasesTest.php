<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Actions\GenerateAuthenticationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\GenerateRegistrationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\VerifyAuthenticationAction;
use RoundlyConsulting\Passkeys\Actions\VerifyRegistrationAction;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAuthenticatorData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Exceptions\OriginMismatch;
use RoundlyConsulting\Passkeys\Exceptions\SignatureInvalid;
use RoundlyConsulting\Passkeys\Exceptions\UserVerificationRequired;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\CborEncoder;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Katherine', 'email' => 'k@example.com']);
    $this->vectors = WebAuthnVectors::es256();

    $options = app(GenerateRegistrationOptionsAction::class)->execute($this->user);
    app(VerifyRegistrationAction::class)->execute($this->user, RegistrationResponseData::fromArray(
        $this->vectors->registrationResponse(['challenge' => $options->challenge, 'ceremonyId' => $options->ceremonyId]),
    ));
});

/**
 * @param  array<string, mixed>  $overrides
 */
function assertAgainst(WebAuthnVectors $vectors, array $overrides): Passkey
{
    $options = app(GenerateAuthenticationOptionsAction::class)->execute();
    $payload = $vectors->assertionResponse(array_merge([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
        'signCount' => 2,
    ], $overrides));

    return app(VerifyAuthenticationAction::class)->execute(AuthenticationResponseData::fromArray($payload));
}

it('rejects an assertion whose client data type is not webauthn.get', function (): void {
    assertAgainst($this->vectors, ['type' => 'webauthn.create']);
})->throws(InvalidClientData::class);

it('rejects a cross-origin assertion by default', function (): void {
    assertAgainst($this->vectors, ['crossOrigin' => true]);
})->throws(OriginMismatch::class);

it('rejects an assertion with the user-presence flag cleared', function (): void {
    assertAgainst($this->vectors, ['flags' => 0x04]); // UV only, no UP
})->throws(InvalidAuthenticatorData::class);

it('rejects an assertion without user verification when required', function (): void {
    assertAgainst($this->vectors, ['flags' => 0x01]); // UP only, no UV
})->throws(UserVerificationRequired::class);

it('rejects an assertion with inconsistent backup-state flags', function (): void {
    assertAgainst($this->vectors, ['flags' => 0x15]); // UP|UV|BS, no BE
})->throws(InvalidAuthenticatorData::class);

it('rejects an assertion when the stored public key is not decodable base64', function (): void {
    Passkey::query()->update(['public_key' => '@@not base64@@']);

    assertAgainst($this->vectors, []);
})->throws(SignatureInvalid::class);

it('rejects an assertion when the stored public key is not a COSE map', function (): void {
    Passkey::query()->update(['public_key' => base64_encode(CborEncoder::uint(9))]);

    assertAgainst($this->vectors, []);
})->throws(SignatureInvalid::class);
