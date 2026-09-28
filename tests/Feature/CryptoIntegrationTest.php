<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Cose\CoseAlgorithm;
use RoundlyConsulting\Crypto\Signature\Ec\Der;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Enums\CeremonyType;
use RoundlyConsulting\Passkeys\Enums\SignCountPolicy;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Events\PasskeySignCountRegressed;
use RoundlyConsulting\Passkeys\Exceptions\ChallengeExpired;
use RoundlyConsulting\Passkeys\Exceptions\ChallengeMismatch;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAuthenticatorData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidConfiguration;
use RoundlyConsulting\Passkeys\Exceptions\OriginMismatch;
use RoundlyConsulting\Passkeys\Exceptions\RpIdMismatch;
use RoundlyConsulting\Passkeys\Exceptions\SignatureInvalid;
use RoundlyConsulting\Passkeys\Exceptions\SignCountRegression;
use RoundlyConsulting\Passkeys\Exceptions\UserVerificationRequired;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\CredentialCrypto;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

/*
 * The relying party running on crypto-for-laravel.
 *
 * Two things are proven here and nothing else matters as much:
 *
 *  1. PERSISTENCE — a passkey registered by the pre-crypto implementation still
 *     authenticates, byte-for-byte, on the crypto one. Getting this wrong locks
 *     every user out of their account permanently.
 *  2. CEREMONY — the WebAuthn checks that make a passkey a passkey (challenge,
 *     origin, rpIdHash, UP/UV, sign count, signature integrity) still reject what
 *     they always rejected. crypto owns the maths; the trust policy stays here.
 */

/**
 * @return array<string, mixed>
 */
function frozen(): array
{
    /** @var array<string, mixed> $fixture */
    $fixture = require __DIR__.'/../Fixtures/frozen-credentials.php';

    return $fixture;
}

/**
 * Seed a passkey exactly as the PRE-RETROFIT code wrote it into the database.
 */
function frozenPasskey(string $algorithm, int $signCount = 0): Passkey
{
    $frozen = frozen();

    /** @var array<string, array<string, string>> $algorithms */
    $algorithms = $frozen['algorithms'];

    $user = User::query()->create([
        'name' => 'Grace',
        'email' => 'grace@example.com',
        'passkey_user_handle' => $frozen['user_handle'],
    ]);

    return Passkey::query()->create([
        'authenticatable_type' => $user->getMorphClass(),
        'authenticatable_id' => $user->getKey(),
        'credential_id' => $frozen['stored_credential_id'],
        'credential_id_hash' => $frozen['stored_credential_id_hash'],
        'public_key' => $algorithms[$algorithm]['stored_public_key'],
        'user_handle' => $frozen['user_handle'],
        'transports' => ['internal'],
        'sign_count' => $signCount,
        'attestation_format' => 'none',
    ]);
}

/**
 * The genuine, frozen assertion that credential produced — as a browser payload.
 *
 * @return array<string, mixed>
 */
function frozenAssertion(string $algorithm): array
{
    $frozen = frozen();

    /** @var array<string, array<string, string>> $algorithms */
    $algorithms = $frozen['algorithms'];

    return [
        'rawId' => Base64Url::encode((string) hex2bin($frozen['credential_id_raw_hex'])),
        'type' => 'public-key',
        'response' => [
            'clientDataJSON' => Base64Url::encode($frozen['client_data_json']),
            'authenticatorData' => Base64Url::encode((string) hex2bin($frozen['authenticator_data_hex'])),
            'signature' => Base64Url::encode((string) hex2bin($algorithms[$algorithm]['signature_hex'])),
            // Unsigned (it is not part of authData or clientDataJSON): the handle
            // a discoverable credential returns, which a usernameless ceremony requires.
            'userHandle' => $frozen['user_handle'],
        ],
        'ceremonyId' => 'frozen',
    ];
}

function storeFrozenChallenge(): void
{
    app(ChallengeRepository::class)->put('frozen', new ChallengeData(
        challenge: frozen()['challenge'],
        userVerification: UserVerification::Required,
        algorithms: [-7, -257, -8],
        type: CeremonyType::Authentication,
    ), 60);
}

beforeEach(function (): void {
    config()->set('passkeys.algorithms', [-7, -257, -8]);
});

// ---------------------------------------------------------------------------
// 1. Persisted credentials: the lock-out guard
// ---------------------------------------------------------------------------

it('writes the exact at-rest bytes the pre-crypto implementation wrote', function (string $algorithm): void {
    $frozen = frozen();

    /** @var array<string, array<string, string>> $algorithms */
    $algorithms = $frozen['algorithms'];

    $rawCredentialId = (string) hex2bin($frozen['credential_id_raw_hex']);
    $coseKeyBytes = (string) hex2bin($algorithms[$algorithm]['cose_hex']);

    // credential_id: base64url, unpadded — crypto's codec, the old codec's bytes.
    expect(Base64Url::encode($rawCredentialId))->toBe($frozen['stored_credential_id']);

    // credential_id_hash: the sha-256 hex the unique index is built on.
    expect(Passkey::hashCredentialId($frozen['stored_credential_id']))
        ->toBe($frozen['stored_credential_id_hash']);

    // public_key: standard, PADDED base64 of the COSE key — NOT base64url.
    expect(Base64::encode($coseKeyBytes))->toBe($algorithms[$algorithm]['stored_public_key']);

    // …and crypto's strict decoder accepts every byte already in the database.
    expect(Base64::decode($algorithms[$algorithm]['stored_public_key']))->toBe($coseKeyBytes);
})->with(['es256', 'rs256', 'eddsa']);

it('still authenticates a passkey registered before the crypto retrofit', function (string $algorithm): void {
    $passkey = frozenPasskey($algorithm);
    storeFrozenChallenge();

    $authenticated = Passkeys::authenticate(
        AuthenticationResponseData::fromArray(frozenAssertion($algorithm)),
    );

    expect($authenticated->is($passkey))->toBeTrue()
        ->and($authenticated->fresh()->sign_count)->toBe(7);
})->with(['es256', 'rs256', 'eddsa']);

it('rejects a tampered signature against a pre-crypto credential', function (string $algorithm): void {
    frozenPasskey($algorithm);
    storeFrozenChallenge();

    $assertion = frozenAssertion($algorithm);
    $frozen = frozen();

    /** @var array<string, array<string, string>> $algorithms */
    $algorithms = $frozen['algorithms'];

    $signature = (string) hex2bin($algorithms[$algorithm]['signature_hex']);
    $signature[strlen($signature) - 1] = $signature[strlen($signature) - 1] === "\x00" ? "\x01" : "\x00";

    $assertion['response']['signature'] = Base64Url::encode($signature);

    Passkeys::authenticate(AuthenticationResponseData::fromArray($assertion));
})->with(['es256', 'rs256', 'eddsa'])->throws(SignatureInvalid::class);

// ---------------------------------------------------------------------------
// 2. Both ceremonies, end to end, on every supported algorithm
// ---------------------------------------------------------------------------

it('registers and then authenticates a fresh credential', function (string $algorithm): void {
    /** @var WebAuthnVectors $vector */
    $vector = WebAuthnVectors::{$algorithm}();

    $user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);

    // Registration (attestation).
    $options = $user->passkeyRegistrationOptions();

    $passkey = $user->registerPasskey(RegistrationResponseData::fromArray($vector->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ])));

    expect($passkey->credential_id)->toBe(Base64Url::encode($vector->credentialId()))
        // The at-rest encoding of a newly registered credential is the same
        // padded base64 an old one carries.
        ->and($passkey->public_key)->toBe($vector->storedPublicKey());

    // Authentication (assertion) with the credential just registered.
    $request = $user->passkeyAuthenticationOptions();

    $authenticated = Passkeys::authenticate(AuthenticationResponseData::fromArray($vector->assertionResponse([
        'challenge' => $request->challenge,
        'ceremonyId' => $request->ceremonyId,
        'signCount' => 9,
    ])));

    expect($authenticated->is($passkey))->toBeTrue()
        ->and($authenticated->fresh()->sign_count)->toBe(9);
})->with(['es256', 'rs256', 'eddsa']);

it('reads the algorithm off the credential, never off the assertion', function (string $algorithm, int $cose): void {
    /** @var WebAuthnVectors $vector */
    $vector = WebAuthnVectors::{$algorithm}();

    $user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);
    $options = $user->passkeyRegistrationOptions();

    $passkey = $user->registerPasskey(RegistrationResponseData::fromArray($vector->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ])));

    // The COSE key stored for this credential pins the verification algorithm:
    // nothing in the assertion payload names one, so there is no algorithm to
    // confuse. The identifiers are the IANA COSE ones, unchanged.
    $key = app(CredentialCrypto::class)->storedPublicKey($passkey);

    expect(app(CredentialCrypto::class)->coseAlgorithm($key)->value)
        ->toBe($cose)
        ->toBe($vector->coseAlgorithm());
})->with([
    ['es256', -7],
    ['rs256', -257],
    ['eddsa', -8],
]);

// ---------------------------------------------------------------------------
// 3. The ceremony still rejects every attack it always rejected
// ---------------------------------------------------------------------------

it('rejects a replayed challenge (the challenge is single-use)', function (): void {
    $vector = WebAuthnVectors::es256();
    $user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);

    $options = $user->passkeyRegistrationOptions();
    $payload = $vector->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ]);

    $user->registerPasskey(RegistrationResponseData::fromArray($payload));

    // Replaying the very same ceremony finds no challenge to pull.
    $user->registerPasskey(RegistrationResponseData::fromArray($payload));
})->throws(ChallengeExpired::class);

it('rejects a challenge that was never issued', function (): void {
    frozenPasskey('es256');
    storeFrozenChallenge();

    $assertion = frozenAssertion('es256');
    $assertion['response']['clientDataJSON'] = Base64Url::encode((string) json_encode([
        'type' => 'webauthn.get',
        'challenge' => Base64Url::encode(str_repeat("\x99", 32)),
        'origin' => 'https://example.com',
        'crossOrigin' => false,
    ]));

    Passkeys::authenticate(AuthenticationResponseData::fromArray($assertion));
})->throws(ChallengeMismatch::class);

it('rejects a wrong origin', function (): void {
    $vector = WebAuthnVectors::es256();
    $user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);
    $options = $user->passkeyRegistrationOptions();

    $user->registerPasskey(RegistrationResponseData::fromArray($vector->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
        'origin' => 'https://evil.example',
    ])));
})->throws(OriginMismatch::class);

it('rejects a wrong rpIdHash', function (): void {
    $vector = WebAuthnVectors::es256();
    $user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);
    $options = $user->passkeyRegistrationOptions();

    $user->registerPasskey(RegistrationResponseData::fromArray($vector->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
        'rpId' => 'attacker.example',
    ])));
})->throws(RpIdMismatch::class);

it('rejects an assertion with user presence unset', function (): void {
    $vector = WebAuthnVectors::es256();
    $user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);
    $options = $user->passkeyRegistrationOptions();

    $user->registerPasskey(RegistrationResponseData::fromArray($vector->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ])));

    $request = $user->passkeyAuthenticationOptions();

    Passkeys::authenticate(AuthenticationResponseData::fromArray($vector->assertionResponse([
        'challenge' => $request->challenge,
        'ceremonyId' => $request->ceremonyId,
        'flags' => 0x04, // UV without UP
    ])));
})->throws(InvalidAuthenticatorData::class);

it('rejects an assertion with user verification unset when required', function (): void {
    $vector = WebAuthnVectors::es256();
    $user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);
    $options = $user->passkeyRegistrationOptions();

    $user->registerPasskey(RegistrationResponseData::fromArray($vector->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ])));

    $request = $user->passkeyAuthenticationOptions();

    Passkeys::authenticate(AuthenticationResponseData::fromArray($vector->assertionResponse([
        'challenge' => $request->challenge,
        'ceremonyId' => $request->ceremonyId,
        'flags' => 0x01, // UP without UV
    ])));
})->throws(UserVerificationRequired::class);

it('rejects a regressed sign count under the strict policy', function (): void {
    config()->set('passkeys.sign_count_policy', SignCountPolicy::Reject->value);

    frozenPasskey('es256', signCount: 99);
    storeFrozenChallenge();

    // The frozen assertion reports counter 7 — a regression from the stored 99,
    // which is how a cloned authenticator gives itself away.
    Passkeys::authenticate(AuthenticationResponseData::fromArray(frozenAssertion('es256')));
})->throws(SignCountRegression::class);

it('flags a regressed sign count under the permissive policy', function (): void {
    Event::fake([PasskeySignCountRegressed::class]);

    config()->set('passkeys.sign_count_policy', SignCountPolicy::Flag->value);

    frozenPasskey('es256', signCount: 99);
    storeFrozenChallenge();

    Passkeys::authenticate(AuthenticationResponseData::fromArray(frozenAssertion('es256')));

    Event::assertDispatched(PasskeySignCountRegressed::class);
});

it('rejects an assertion signed over different data', function (): void {
    $vector = WebAuthnVectors::es256();
    $user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);
    $options = $user->passkeyRegistrationOptions();

    $user->registerPasskey(RegistrationResponseData::fromArray($vector->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ])));

    $request = $user->passkeyAuthenticationOptions();

    Passkeys::authenticate(AuthenticationResponseData::fromArray($vector->assertionResponse([
        'challenge' => $request->challenge,
        'ceremonyId' => $request->ceremonyId,
        'tamperSignedData' => true,
    ])));
})->throws(SignatureInvalid::class);

// ---------------------------------------------------------------------------
// 4. Codec strictness and the narrowed algorithm allow-list
// ---------------------------------------------------------------------------

it('rejects a response member that is not strict base64url', function (string $member, string $value): void {
    $vector = WebAuthnVectors::es256();
    $payload = $vector->assertionResponse();
    $payload['response'][$member] = $value;

    AuthenticationResponseData::fromArray($payload);
})->with([
    // standard-base64 alphabet, stray padding, and an out-of-alphabet byte are
    // all refused rather than silently decoding to different bytes.
    ['signature', 'AAAA+/=='],
    ['clientDataJSON', 'not base64url!'],
    ['authenticatorData', 'AAAA='],
])->throws(InvalidClientData::class);

it('accepts an ES256 signature in either the DER or the raw r‖s form', function (): void {
    // Authenticators deliver ECDSA as ASN.1 DER (the frozen signature is DER, and
    // it authenticates above). crypto normalises DER → raw internally, and also
    // accepts a signature already in the raw 64-byte form. Both must verify; a
    // wrong-length one must not.
    $frozen = frozen();

    /** @var array<string, array<string, string>> $algorithms */
    $algorithms = $frozen['algorithms'];

    $der = (string) hex2bin($algorithms['es256']['signature_hex']);

    expect($der[0])->toBe("\x30"); // a DER SEQUENCE, exactly as delivered

    $raw = Der::toRaw($der);

    expect(strlen($raw))->toBe(64)
        ->and(Der::fromRaw($raw))->toBe($der);

    frozenPasskey('es256');
    storeFrozenChallenge();

    $assertion = frozenAssertion('es256');
    $assertion['response']['signature'] = Base64Url::encode($raw);

    expect(Passkeys::authenticate(AuthenticationResponseData::fromArray($assertion)))
        ->toBeInstanceOf(Passkey::class);
});

it('rejects a registration response carrying no attested credential data', function (): void {
    $vector = WebAuthnVectors::es256();
    $user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);
    $options = $user->passkeyRegistrationOptions();

    $user->registerPasskey(RegistrationResponseData::fromArray($vector->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
        'flags' => 0x05, // UP | UV, but no AT: no credential to store
    ])));
})->throws(InvalidAuthenticatorData::class);

it('rejects a registration response with no ceremony to bind it to', function (): void {
    $vector = WebAuthnVectors::es256();
    $user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);
    $user->passkeyRegistrationOptions();

    $payload = $vector->registrationResponse();
    unset($payload['ceremonyId']);

    $user->registerPasskey(RegistrationResponseData::fromArray($payload));
})->throws(ChallengeExpired::class);

it('refuses to build options from a corrupted stored credential id', function (string $method): void {
    $user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);

    Passkey::query()->create([
        'authenticatable_type' => $user->getMorphClass(),
        'authenticatable_id' => $user->getKey(),
        'credential_id' => 'not*valid*base64url',
        'credential_id_hash' => Passkey::hashCredentialId('not*valid*base64url'),
        'public_key' => frozen()['algorithms']['es256']['stored_public_key'],
        'user_handle' => $user->passkeyUserHandle(),
        'sign_count' => 0,
    ]);

    $user->{$method}();
})->with([
    ['passkeyRegistrationOptions'],
    ['passkeyAuthenticationOptions'],
])->throws(InvalidClientData::class);

it('accepts only the COSE algorithms this relying party has vetted', function (): void {
    expect(PasskeyConfig::SUPPORTED_ALGORITHMS)->toBe([
        CoseAlgorithm::ES256,
        CoseAlgorithm::RS256,
        CoseAlgorithm::EdDSA,
    ]);
});

it('refuses a configured algorithm crypto knows but this package does not', function (): void {
    // crypto's COSE registry also carries ES384 (-35) and ES512 (-36); a relying
    // party must not silently inherit them through the shared enum.
    PasskeyConfig::fromArray(['algorithms' => [CoseAlgorithm::ES384->value]]);
})->throws(InvalidConfiguration::class);
