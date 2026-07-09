<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Actions;

use Illuminate\Support\Str;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CredentialDescriptor;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\Base64Url;

/**
 * Builds PublicKeyCredentialCreationOptions for a registration ceremony and
 * stores the single-use challenge keyed by a fresh ceremony id.
 */
final class GenerateRegistrationOptionsAction
{
    public function __construct(
        private readonly ChallengeRepository $challenges,
        private readonly PasskeyConfig $config,
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
        $challenge = Base64Url::encode(random_bytes(max(16, $this->config->challengeBytes)));

        $this->challenges->put(
            $ceremonyId,
            new ChallengeData(
                challenge: $challenge,
                userVerification: $userVerification,
                algorithms: $this->config->algorithms,
                userHandle: $user->passkeyUserHandle(),
            ),
            $this->config->challengeTtl,
        );

        return new CreationOptionsData(
            ceremonyId: $ceremonyId,
            rpId: $rpId,
            rpName: $this->config->rpName,
            userHandle: Base64Url::decode($user->passkeyUserHandle()),
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
                id: Base64Url::decode($passkey->credential_id),
                transports: $passkey->transports,
            ))
            ->all());
    }

    private function ceremonyId(): string
    {
        return Str::random(40);
    }
}
