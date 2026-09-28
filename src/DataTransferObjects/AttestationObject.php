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
     * WebAuthn §8.1: an attestation statement format identifier is at most 32
     * octets of printable US-ASCII, excluding backslash and double quote (VCHAR
     * without %x22 and %x5C). Held here, at the parse boundary, so a hostile
     * `fmt` is a clean client-data refusal under every trust tier — `ignore`
     * included, which stores the format verbatim — and never reaches the
     * `attestation_format` column.
     */
    private const string FORMAT_IDENTIFIER = '/\A[\x21\x23-\x5B\x5D-\x7E]{1,32}\z/';

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

        if (preg_match(self::FORMAT_IDENTIFIER, $format) !== 1) {
            throw InvalidClientData::malformed();
        }

        return new self(
            format: $format,
            statement: $statement,
            authenticatorData: $authData,
        );
    }
}
