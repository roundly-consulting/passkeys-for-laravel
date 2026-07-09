<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Actions;

use Illuminate\Support\Str;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CredentialDescriptor;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\Base64Url;

/**
 * Builds PublicKeyCredentialRequestOptions for an authentication ceremony and
 * stores the single-use challenge. A null user yields a discoverable
 * (usernameless) request with an empty allowCredentials list.
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

        $ceremonyId = Str::random(40);
        $challenge = Base64Url::encode(random_bytes(max(16, $this->config->challengeBytes)));

        $this->challenges->put(
            $ceremonyId,
            new ChallengeData(
                challenge: $challenge,
                userVerification: $this->config->userVerification,
                algorithms: $this->config->algorithms,
            ),
            $this->config->challengeTtl,
        );

        return new RequestOptionsData(
            ceremonyId: $ceremonyId,
            rpId: $rpId,
            challenge: $challenge,
            timeoutMs: $this->config->timeoutMs,
            userVerification: $this->config->userVerification,
            allowCredentials: $user === null ? [] : $this->allowCredentials($user),
        );
    }

    /**
     * @return list<CredentialDescriptor>
     */
    private function allowCredentials(HasPasskeys $user): array
    {
        return array_values($user->passkeys()->get()
            ->map(static fn (Passkey $passkey): CredentialDescriptor => new CredentialDescriptor(
                id: Base64Url::decode($passkey->credential_id),
                transports: $passkey->transports,
            ))
            ->all());
    }
}
