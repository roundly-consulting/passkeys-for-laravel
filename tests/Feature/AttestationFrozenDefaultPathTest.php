<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Actions\GenerateRegistrationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\VerifyRegistrationAction;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\CborEncoder;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

/*
 * FROZEN default-path vector.
 *
 * Minted against the PRE-ATTESTATION engine (attestation_trust = ignore,
 * reject_unknown_fmt = false — the shipped defaults) and asserted byte-for-byte
 * afterwards. `Ignore` is the default posture: a host that never touches config
 * must see ZERO behaviour change when the attestation gate lands.
 *
 * Every row below carries an attestation statement whose maths is nonsense. Under
 * `Ignore` the statement is never read: the format is recorded, the credential
 * enrols, and the at-rest encodings stay exactly what they always were. If one of
 * these ever fails, the gate stopped short-circuiting and started verifying by
 * default — which would silently refuse authenticators every host enrols today.
 */

/**
 * @param  array<string, mixed>  $overrides
 */
function registerUnderDefaults(User $user, WebAuthnVectors $vectors, array $overrides = []): Passkey
{
    $options = app(GenerateRegistrationOptionsAction::class)->execute($user);

    $payload = $vectors->registrationResponse(array_merge([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ], $overrides));

    return app(VerifyRegistrationAction::class)->execute($user, RegistrationResponseData::fromArray($payload));
}

/** An attestation statement that no verifier on earth would accept. */
function bogusStatement(): string
{
    return CborEncoder::map([
        [CborEncoder::tstr('alg'), CborEncoder::nint(-7)],
        [CborEncoder::tstr('sig'), CborEncoder::bstr(str_repeat("\x00", 8))],
        [CborEncoder::tstr('x5c'), CborEncoder::arr([CborEncoder::bstr('not-a-certificate')])],
    ]);
}

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Ada', 'email' => 'ada@example.com']);
});

it('ships ignore as the default attestation trust', function (): void {
    expect(config('passkeys.attestation_trust'))->toBe('ignore')
        ->and(config('passkeys.reject_unknown_fmt'))->toBeFalse();
});

it('enrols every attestation format under the default posture, statement unread', function (string $format): void {
    $vectors = WebAuthnVectors::es256();

    $passkey = registerUnderDefaults($this->user, $vectors, [
        'fmt' => $format,
        'attStmt' => bogusStatement(),
        'aaguid' => str_repeat("\x11", 16),
    ]);

    expect($passkey->exists)->toBeTrue()
        ->and($passkey->attestation_format)->toBe($format)
        ->and($passkey->aaguid)->toBe('11111111-1111-1111-1111-111111111111');
})->with(['none', 'packed', 'tpm', 'apple', 'android-key', 'android-safetynet', 'fido-u2f', 'not-a-format']);

it('freezes the at-rest encodings the default path writes', function (): void {
    $vectors = WebAuthnVectors::es256()->withCredentialId(hex2bin('a1b2c3d4e5f60718293a4b5c6d7e8f9012345678') ?: '');

    $passkey = registerUnderDefaults($this->user, $vectors, [
        'fmt' => 'packed',
        'attStmt' => bogusStatement(),
    ]);

    // credential_id: UNPADDED base64url. public_key: STANDARD, PADDED base64.
    // Swapping either locks every registered user out of their account.
    expect($passkey->credential_id)->toBe('obLD1OX2BxgpOktcbX6PkBI0Vng')
        ->and($passkey->credential_id_hash)->toBe(hash('sha256', 'obLD1OX2BxgpOktcbX6PkBI0Vng'))
        ->and($passkey->public_key)->toBe(base64_encode($vectors->coseKey()))
        ->and($passkey->public_key)->not->toContain('-')
        ->and($passkey->public_key)->not->toContain('_')
        ->and($passkey->sign_count)->toBe(0);
});
