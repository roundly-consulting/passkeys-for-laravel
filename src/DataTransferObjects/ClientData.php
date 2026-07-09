<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;

/**
 * The decoded clientDataJSON object (WebAuthn spec §5.8.1). `challenge` stays in
 * its base64url form so it can be compared against the stored challenge without
 * a round-trip through raw bytes.
 */
final readonly class ClientData
{
    public function __construct(
        public string $type,
        public string $challenge,
        public string $origin,
        public bool $crossOrigin,
    ) {}

    /**
     * @throws InvalidClientData
     */
    public static function fromJson(string $json): self
    {
        $decoded = json_decode($json, true);

        if (! is_array($decoded)) {
            throw InvalidClientData::malformed();
        }

        $type = $decoded['type'] ?? null;
        $challenge = $decoded['challenge'] ?? null;
        $origin = $decoded['origin'] ?? null;

        if (! is_string($type) || ! is_string($challenge) || ! is_string($origin)) {
            throw InvalidClientData::malformed();
        }

        return new self(
            type: $type,
            challenge: $challenge,
            origin: $origin,
            crossOrigin: (bool) ($decoded['crossOrigin'] ?? false),
        );
    }
}
