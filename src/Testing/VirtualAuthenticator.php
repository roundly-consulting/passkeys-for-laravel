<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Testing;

use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Crypto\Random\Bytes;
use RoundlyConsulting\Crypto\Signature\Ec\Der;
use RoundlyConsulting\Crypto\Signature\Es;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Testing\TestKeys;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;

/**
 * A software ES256 authenticator for test suites — so a consuming package or host
 * can run REAL registration and authentication ceremonies through the real verifier
 * (challenge, origin, rpIdHash, flags, signature, sign counter) instead of faking
 * the service or re-implementing WebAuthn test vectors.
 *
 * TEST-ONLY. It holds a throwaway key from crypto's `TestKeys`, attests with `none`,
 * and never belongs in production code. It lives in runtime autoload purely so other
 * packages' suites can reach it, like {@see PasskeysFake}.
 *
 * ```php
 * $authenticator = VirtualAuthenticator::es256();
 * $user->registerPasskey($authenticator->register($user->passkeyRegistrationOptions()));
 * $passkey = Passkeys::for($user)->authenticate($authenticator->assert(Passkeys::for($user)->authenticationOptions()));
 * ```
 *
 * It answers any options it is handed — even ones whose allowCredentials does not name
 * it — so a suite can also play the attacker and prove the server refuses.
 */
final class VirtualAuthenticator
{
    private const FLAG_USER_PRESENT = 0x01;

    private const FLAG_USER_VERIFIED = 0x04;

    private const FLAG_ATTESTED_DATA = 0x40;

    private int $signCount = 0;

    /** The raw user handle of the account it was registered for, when discoverable. */
    private ?string $userHandle = null;

    private function __construct(
        private readonly EcKey $key,
        private readonly string $rawCredentialId,
        private readonly ?string $rpId,
        private readonly ?string $origin,
    ) {}

    /**
     * A fresh P-256 credential. The RP ID defaults to the one each options object
     * carries, the origin to the first configured `passkeys.origins` entry.
     */
    public static function es256(?string $rpId = null, ?string $origin = null): self
    {
        return new self(TestKeys::ec(), Bytes::generate(32), $rpId, $origin);
    }

    /**
     * Answer a registration ceremony with a `none`-attested credential. A resident
     * (discoverable) credential remembers the account's handle and returns it on
     * every assertion; a non-resident one returns none, as browsers do.
     */
    public function register(CreationOptionsData $options, bool $residentKey = true): RegistrationResponseData
    {
        $this->userHandle = $residentKey ? $options->userHandle : null;

        $coordinates = $this->key->coordinates();

        $coseKey = CborEncoder::map([
            [CborEncoder::uint(1), CborEncoder::uint(2)],   // kty: EC2
            [CborEncoder::uint(3), CborEncoder::nint(-7)],  // alg: ES256
            [CborEncoder::nint(-1), CborEncoder::uint(1)],  // crv: P-256
            [CborEncoder::nint(-2), CborEncoder::bstr($coordinates->x)],
            [CborEncoder::nint(-3), CborEncoder::bstr($coordinates->y)],
        ]);

        $attestedCredentialData = str_repeat("\x00", 16) // AAGUID: none disclosed
            .pack('n', strlen($this->rawCredentialId))
            .$this->rawCredentialId
            .$coseKey;

        $authenticatorData = $this->authenticatorData(
            $options->rpId,
            self::FLAG_USER_PRESENT | self::FLAG_USER_VERIFIED | self::FLAG_ATTESTED_DATA,
            $this->signCount,
        ).$attestedCredentialData;

        $attestationObject = CborEncoder::map([
            [CborEncoder::tstr('fmt'), CborEncoder::tstr('none')],
            [CborEncoder::tstr('attStmt'), CborEncoder::map([])],
            [CborEncoder::tstr('authData'), CborEncoder::bstr($authenticatorData)],
        ]);

        return new RegistrationResponseData(
            rawId: $this->rawCredentialId,
            clientDataJson: $this->clientDataJson('webauthn.create', $options->challenge),
            attestationObject: $attestationObject,
            transports: ['internal'],
            ceremonyId: $options->ceremonyId,
        );
    }

    /**
     * Answer an authentication ceremony with a signed assertion. The counter advances
     * by one per assertion unless an explicit `$signCount` is given (e.g. a lower one,
     * to simulate a cloned authenticator). `$userVerified: false` sends a
     * presence-only assertion, to prove a UV requirement is enforced.
     */
    public function assert(RequestOptionsData $options, bool $userVerified = true, ?int $signCount = null): AuthenticationResponseData
    {
        $this->signCount = $signCount ?? $this->signCount + 1;

        $flags = self::FLAG_USER_PRESENT | ($userVerified ? self::FLAG_USER_VERIFIED : 0);
        $authenticatorData = $this->authenticatorData($options->rpId, $flags, $this->signCount);
        $clientDataJson = $this->clientDataJson('webauthn.get', $options->challenge);

        // Authenticators deliver ECDSA signatures ASN.1 DER-encoded; crypto signs in
        // the JOSE raw r‖s form, so convert.
        $signature = Der::fromRaw(
            (new Es($this->key))->sign($authenticatorData.(new Digest)->raw($clientDataJson)),
            $this->key->coordinateBytes(),
        );

        return new AuthenticationResponseData(
            rawId: $this->rawCredentialId,
            clientDataJson: $clientDataJson,
            authenticatorData: $authenticatorData,
            signature: $signature,
            userHandle: $this->userHandle,
            ceremonyId: $options->ceremonyId,
        );
    }

    /**
     * The credential id, base64url — what the relying party stores in `credential_id`.
     */
    public function credentialId(): string
    {
        return Base64Url::encode($this->rawCredentialId);
    }

    private function authenticatorData(string $optionsRpId, int $flags, int $signCount): string
    {
        return (new Digest)->raw($this->rpId ?? $optionsRpId).chr($flags).pack('N', $signCount);
    }

    private function clientDataJson(string $type, string $challenge): string
    {
        return (string) json_encode([
            'type' => $type,
            'challenge' => $challenge,
            'origin' => $this->origin ?? app(PasskeyConfig::class)->requireOrigins()[0],
            'crossOrigin' => false,
        ], JSON_UNESCAPED_SLASHES);
    }
}
