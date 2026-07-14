<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;

/**
 * A browser registration (attestation) response, decoded from the host-validated
 * payload. Binary members arrive base64url-encoded and are decoded to raw bytes
 * here — the single sanctioned shape-array boundary; everything downstream typed.
 */
final readonly class RegistrationResponseData
{
    /**
     * @param  list<string>  $transports
     */
    public function __construct(
        public string $rawId,
        public string $clientDataJson,
        public string $attestationObject,
        public array $transports = [],
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
        $attestationObject = $response['attestationObject'] ?? null;

        if (! is_string($rawId) || ! is_string($clientDataJson) || ! is_string($attestationObject)) {
            throw InvalidClientData::malformed();
        }

        /** @var list<string> $transports */
        $transports = array_values(array_filter(
            is_array($response['transports'] ?? null) ? $response['transports'] : [],
            'is_string',
        ));

        $ceremonyId = $payload['ceremonyId'] ?? null;

        // crypto's base64url codec is strict: it rejects standard-base64 chars,
        // stray padding and anything outside the alphabet, so a tampered member
        // never silently decodes into different bytes.
        try {
            return new self(
                rawId: Base64Url::decode($rawId),
                clientDataJson: Base64Url::decode($clientDataJson),
                attestationObject: Base64Url::decode($attestationObject),
                transports: $transports,
                ceremonyId: is_string($ceremonyId) ? $ceremonyId : null,
            );
        } catch (InvalidEncodingException) {
            throw InvalidClientData::malformed();
        }
    }
}
