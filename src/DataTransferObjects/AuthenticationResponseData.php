<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Support\Base64Url;

/**
 * A browser authentication (assertion) response, decoded from the host-validated
 * payload. Binary members arrive base64url-encoded and are decoded to raw bytes.
 */
final readonly class AuthenticationResponseData
{
    public function __construct(
        public string $rawId,
        public string $clientDataJson,
        public string $authenticatorData,
        public string $signature,
        public ?string $userHandle = null,
        public ?string $ceremonyId = null,
    ) {}

    /**
     * @param  array<string, mixed>  $payload
     *
     * @throws InvalidClientData
     */
    public static function fromArray(array $payload): self
    {
        $response = $payload['response'] ?? null;

        if (! is_array($response)) {
            throw InvalidClientData::malformed();
        }

        $rawId = $payload['rawId'] ?? $payload['id'] ?? null;
        $clientDataJson = $response['clientDataJSON'] ?? null;
        $authenticatorData = $response['authenticatorData'] ?? null;
        $signature = $response['signature'] ?? null;

        if (! is_string($rawId) || ! is_string($clientDataJson)
            || ! is_string($authenticatorData) || ! is_string($signature)) {
            throw InvalidClientData::malformed();
        }

        $userHandle = $response['userHandle'] ?? null;
        $ceremonyId = $payload['ceremonyId'] ?? null;

        return new self(
            rawId: Base64Url::decode($rawId),
            clientDataJson: Base64Url::decode($clientDataJson),
            authenticatorData: Base64Url::decode($authenticatorData),
            signature: Base64Url::decode($signature),
            userHandle: is_string($userHandle) && $userHandle !== '' ? Base64Url::decode($userHandle) : null,
            ceremonyId: is_string($ceremonyId) ? $ceremonyId : null,
        );
    }
}
