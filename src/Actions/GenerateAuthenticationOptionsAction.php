<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Actions;

use Illuminate\Support\Str;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Random\Bytes;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CredentialDescriptor;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Enums\CeremonyType;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * Builds PublicKeyCredentialRequestOptions for an authentication ceremony and
 * stores the single-use challenge. A null user yields a discoverable
 * (usernameless) request with an empty allowCredentials list.
 *
 * A request for a known user binds the stored challenge to that user's handle and
 * to the exact credentials offered in allowCredentials, so the ceremony can only be
 * completed with one of them — never with another account's passkey.
 */
final class GenerateAuthenticationOptionsAction
{
    public function __construct(
        private readonly ChallengeRepository $challenges,
        private readonly PasskeyConfig $config,
    ) {}

    public function execute(?HasPasskeys $user = null): RequestOptionsData
    {
        $rpId = $this->config->requireRpId();
        $this->config->requireOrigins();

        $userVerification = $this->config->userVerification;
        $passkeys = $user === null ? [] : array_values($user->passkeys()->get()->all());

        $ceremonyId = Str::random(40);
        $challenge = Base64Url::encode(Bytes::generate(max(16, $this->config->challengeBytes)));

        $this->challenges->put(
            $ceremonyId,
            new ChallengeData(
                challenge: $challenge,
                userVerification: $userVerification,
                algorithms: $this->config->algorithms,
                type: CeremonyType::Authentication,
                userHandle: $user?->passkeyUserHandle(),
                allowedCredentialHashes: array_map(
                    static fn (Passkey $passkey): string => $passkey->credential_id_hash,
                    $passkeys,
                ),
            ),
            $this->config->challengeTtl,
        );

        return new RequestOptionsData(
            ceremonyId: $ceremonyId,
            rpId: $rpId,
            challenge: $challenge,
            timeoutMs: $this->config->timeoutMs,
            userVerification: $userVerification,
            allowCredentials: array_map(
                static fn (Passkey $passkey): CredentialDescriptor => new CredentialDescriptor(
                    id: self::decode($passkey->credential_id),
                    transports: $passkey->transports,
                ),
                $passkeys,
            ),
        );
    }

    /**
     * Decode a stored base64url credential id with crypto's strict codec, keeping
     * the malformed-value exception this package has always raised.
     *
     * @throws InvalidClientData
     */
    private static function decode(string $value): string
    {
        try {
            return Base64Url::decode($value);
        } catch (InvalidEncodingException) {
            throw InvalidClientData::malformed();
        }
    }
}
