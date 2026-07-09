<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;

/**
 * The decoded CBOR attestationObject: the format string, the raw attestation
 * statement map, and the raw authenticatorData bytes it wraps.
 */
final readonly class AttestationObject
{
    /**
     * @param  array<int|string, mixed>  $statement
     */
    public function __construct(
        public string $format,
        public array $statement,
        public string $authenticatorData,
    ) {}

    /**
     * @param  mixed  $decoded  the CBOR-decoded attestationObject map
     *
     * @throws InvalidClientData
     */
    public static function fromDecoded(mixed $decoded): self
    {
        if (! is_array($decoded)) {
            throw InvalidClientData::malformed();
        }

        $format = $decoded['fmt'] ?? null;
        $authData = $decoded['authData'] ?? null;
        $statement = $decoded['attStmt'] ?? [];

        if (! is_string($format) || ! is_string($authData) || ! is_array($statement)) {
            throw InvalidClientData::malformed();
        }

        return new self(
            format: $format,
            statement: $statement,
            authenticatorData: $authData,
        );
    }
}
