<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use JsonSerializable;
use RoundlyConsulting\Passkeys\Enums\UserVerification;

/**
 * PublicKeyCredentialRequestOptions, serialised to the exact JSON shape
 * `navigator.credentials.get({ publicKey })` expects. An empty allowCredentials
 * list means a discoverable (usernameless) login.
 */
final readonly class RequestOptionsData implements JsonSerializable
{
    /**
     * @param  list<CredentialDescriptor>  $allowCredentials
     */
    public function __construct(
        public string $ceremonyId,
        public string $rpId,
        public string $challenge,
        public int $timeoutMs,
        public UserVerification $userVerification,
        public array $allowCredentials = [],
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'ceremonyId' => $this->ceremonyId,
            'publicKey' => [
                'challenge' => $this->challenge,
                'rpId' => $this->rpId,
                'timeout' => $this->timeoutMs,
                'userVerification' => $this->userVerification->value,
                'allowCredentials' => array_map(
                    static fn (CredentialDescriptor $descriptor): array => $descriptor->toArray(),
                    $this->allowCredentials,
                ),
            ],
        ];
    }
}
