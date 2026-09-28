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
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CredentialDescriptor;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\Enums\CeremonyType;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * Builds PublicKeyCredentialCreationOptions for a registration ceremony and
 * stores the single-use challenge keyed by a fresh ceremony id.
 */
final readonly class GenerateRegistrationOptionsAction
{
    public function __construct(
        private ChallengeRepository $challenges,
        private PasskeyConfig $config,
    ) {}

    public function execute(HasPasskeys $user, ?RegistrationOptionsOverrides $overrides = null): CreationOptionsData
    {
        $rpId = $this->config->requireRpId();
        $this->config->requireOrigins();

        $overrides ??= new RegistrationOptionsOverrides;

        $userVerification = $overrides->userVerification ?? $this->config->userVerification;
        $attestation = $overrides->attestation ?? $this->config->attestation;
        $timeout = $overrides->timeoutMs ?? $this->config->timeoutMs;

        $ceremonyId = $this->ceremonyId();
        $challenge = Base64Url::encode(Bytes::generate(max(16, $this->config->challengeBytes)));

        $this->challenges->put(
            $ceremonyId,
            new ChallengeData(
                challenge: $challenge,
                userVerification: $userVerification,
                algorithms: $this->config->algorithms,
                type: CeremonyType::Registration,
                userHandle: $user->passkeyUserHandle(),
            ),
            $this->config->challengeTtlFor($timeout),
        );

        return new CreationOptionsData(
            ceremonyId: $ceremonyId,
            rpId: $rpId,
            rpName: $this->config->rpName,
            userHandle: self::decode($user->passkeyUserHandle()),
            userName: $user->passkeyUserName(),
            userDisplayName: $user->passkeyDisplayName(),
            challenge: $challenge,
            algorithms: $this->config->algorithms,
            timeoutMs: $timeout,
            attestation: $attestation,
            userVerification: $userVerification,
            excludeCredentials: $this->excludeCredentials($user),
            residentKey: $overrides->residentKey ?? $this->config->residentKey,
            authenticatorAttachment: $overrides->authenticatorAttachment,
        );
    }

    /**
     * @return list<CredentialDescriptor>
     */
    private function excludeCredentials(HasPasskeys $user): array
    {
        return array_values($user->passkeys()->get()
            ->map(static fn (Passkey $passkey): CredentialDescriptor => new CredentialDescriptor(
                id: self::decode($passkey->credential_id),
                transports: $passkey->transports,
            ))
            ->all());
    }

    /**
     * Decode a stored base64url value (a credential id, a user handle) with
     * crypto's strict codec, keeping the malformed-value exception this package
     * has always raised.
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

    private function ceremonyId(): string
    {
        return Str::random(40);
    }
}
