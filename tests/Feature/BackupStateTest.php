<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Passkeys\Actions\GenerateAuthenticationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\GenerateRegistrationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\VerifyAuthenticationAction;
use RoundlyConsulting\Passkeys\Actions\VerifyRegistrationAction;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAuthenticatorData;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

/*
 * WebAuthn L3 §7.2 steps 18–19 and 26: backup ELIGIBILITY (FLAG_BE) is fixed when the
 * credential is created and must never change; backup STATE (FLAG_BS) is current state
 * and is updated on every accepted assertion.
 */

const FLAGS_UP_UV = 0x05;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;

function enrolWithFlags(User $user, WebAuthnVectors $vectors, int $flags): Passkey
{
    $options = app(GenerateRegistrationOptionsAction::class)->execute($user);
    $payload = $vectors->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
        'flags' => $flags | FLAG_AT,
    ]);

    return app(VerifyRegistrationAction::class)->execute($user, RegistrationResponseData::fromArray($payload));
}

function assertWithFlags(Passkey $passkey, WebAuthnVectors $vectors, int $flags, int $signCount): Passkey
{
    $options = app(GenerateAuthenticationOptionsAction::class)->execute();
    $payload = $vectors->assertionResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
        'flags' => $flags,
        'signCount' => $signCount,
        'userHandle' => Base64Url::decode($passkey->user_handle),
    ]);

    return app(VerifyAuthenticationAction::class)->execute(AuthenticationResponseData::fromArray($payload));
}

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Ada', 'email' => 'ada@example.com']);
    $this->vectors = WebAuthnVectors::es256();
});

it('updates the stored backup state from each accepted assertion', function (): void {
    $passkey = enrolWithFlags($this->user, $this->vectors, FLAGS_UP_UV | FLAG_BE);

    expect($passkey->backup_eligible)->toBeTrue()
        ->and($passkey->backup_state)->toBeFalse();

    expect(assertWithFlags($passkey, $this->vectors, FLAGS_UP_UV | FLAG_BE | FLAG_BS, 1)->backup_state)->toBeTrue()
        ->and($passkey->fresh()?->backup_state)->toBeTrue();

    expect(assertWithFlags($passkey, $this->vectors, FLAGS_UP_UV | FLAG_BE, 2)->backup_state)->toBeFalse()
        ->and($passkey->fresh()?->backup_state)->toBeFalse();
});

it('updates the backup state on a flagged regression too', function (): void {
    $passkey = enrolWithFlags($this->user, $this->vectors, FLAGS_UP_UV | FLAG_BE);
    Passkey::query()->whereKey($passkey->id)->update(['sign_count' => 10]);

    expect(assertWithFlags($passkey, $this->vectors, FLAGS_UP_UV | FLAG_BE | FLAG_BS, 3)->backup_state)->toBeTrue()
        ->and($passkey->fresh()?->backup_state)->toBeTrue()
        ->and($passkey->fresh()?->sign_count)->toBe(10);
});

it('refuses an assertion whose backup eligibility changed since registration', function (int $registered, int $asserted): void {
    $passkey = enrolWithFlags($this->user, $this->vectors, $registered);

    expect(fn () => assertWithFlags($passkey, $this->vectors, $asserted, 1))
        ->toThrow(InvalidAuthenticatorData::class, 'backup eligibility');

    expect($passkey->fresh()?->backup_eligible)->toBe(($registered & FLAG_BE) !== 0)
        ->and($passkey->fresh()?->sign_count)->toBe(0);
})->with([
    'FLAG_BE 0 → 1' => [FLAGS_UP_UV, FLAGS_UP_UV | FLAG_BE | FLAG_BS],
    'FLAG_BE 1 → 0' => [FLAGS_UP_UV | FLAG_BE, FLAGS_UP_UV],
]);
