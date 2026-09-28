<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Passkeys\Actions\GenerateAuthenticationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\GenerateRegistrationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\VerifyAuthenticationAction;
use RoundlyConsulting\Passkeys\Actions\VerifyRegistrationAction;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

/*
 * WebAuthn §7.2 step 6: when the user was NOT identified before the ceremony
 * (usernameless options), response.userHandle must be present and must name the
 * credential's account. When the options were minted for a user, the browser may
 * omit it (a non-discoverable credential), because the ceremony already knows who.
 */

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Katherine', 'email' => 'k@example.com']);
    $this->vectors = WebAuthnVectors::es256();

    $options = app(GenerateRegistrationOptionsAction::class)->execute($this->user);
    $this->passkey = app(VerifyRegistrationAction::class)->execute($this->user, RegistrationResponseData::fromArray(
        $this->vectors->registrationResponse(['challenge' => $options->challenge, 'ceremonyId' => $options->ceremonyId]),
    ));
});

/**
 * @param  array<string, mixed>  $overrides
 */
function assertUsernameless(WebAuthnVectors $vectors, ?User $for, array $overrides = []): Passkey
{
    $options = app(GenerateAuthenticationOptionsAction::class)->execute($for);
    $payload = $vectors->assertionResponse(array_merge([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ], $overrides));

    return app(VerifyAuthenticationAction::class)->execute(AuthenticationResponseData::fromArray($payload));
}

it('refuses a usernameless assertion that carries no user handle', function (): void {
    assertUsernameless($this->vectors, null, ['userHandle' => null]);
})->throws(CredentialNotFound::class);

it('leaves the counter untouched when it refuses a handle-less usernameless assertion', function (): void {
    expect(fn () => assertUsernameless($this->vectors, null, ['signCount' => 7, 'userHandle' => null]))->toThrow(CredentialNotFound::class);

    expect($this->passkey->fresh()?->sign_count)->toBe(0)
        ->and($this->passkey->fresh()?->last_used_at)->toBeNull();
});

it('accepts a usernameless assertion that names the credential\'s account', function (): void {
    $passkey = assertUsernameless($this->vectors, null, ['userHandle' => Base64Url::decode($this->passkey->user_handle)]);

    expect($passkey->is($this->passkey))->toBeTrue();
});

it('accepts a handle-less assertion on options minted for the user', function (): void {
    $passkey = assertUsernameless($this->vectors, $this->user, ['userHandle' => null]);

    expect($passkey->is($this->passkey))->toBeTrue();
});
