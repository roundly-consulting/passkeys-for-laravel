<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Attestation\Statements;

use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAttestation;

/**
 * A typed view over a `packed` attestation statement (WebAuthn §8.2).
 *
 * The decoded CBOR map is attacker-controlled and shapeless; it is turned into
 * this DTO once, at the edge, with an explicit guard per field, so no untyped
 * `mixed` ever reaches the verifier's logic.
 *
 * `x5c` entries are RAW DER byte strings — CBOR carries bytes, not the base64 a
 * JOSE `x5c` header carries. A verifier that base64-decoded them would reject
 * every genuine authenticator.
 */
final readonly class PackedStatement
{
    /**
     * @param  list<string>  $x5c  raw DER certificates, leaf first
     */
    private function __construct(
        public int $algorithm,
        public string $signature,
        public array $x5c,
    ) {}

    /**
     * @throws InvalidAttestation
     */
    public static function fromAttestationObject(AttestationObject $attestation): self
    {
        $statement = $attestation->statement;

        if (array_key_exists('ecdaaKeyId', $statement)) {
            throw InvalidAttestation::ecdaaUnsupported('packed');
        }

        $algorithm = $statement['alg'] ?? null;
        $signature = $statement['sig'] ?? null;

        if (! is_int($algorithm)) {
            throw InvalidAttestation::malformedStatement('packed', 'alg must be a COSE algorithm identifier');
        }

        if (! is_string($signature) || $signature === '') {
            throw InvalidAttestation::malformedStatement('packed', 'sig must be a non-empty byte string');
        }

        return new self($algorithm, $signature, self::x5c($statement));
    }

    /** Whether the statement carries a certificate path (Basic) or not (Self). */
    public function isSelfAttested(): bool
    {
        return $this->x5c === [];
    }

    /**
     * @param  array<int|string, mixed>  $statement
     * @return list<string>
     *
     * @throws InvalidAttestation
     */
    private static function x5c(array $statement): array
    {
        $x5c = $statement['x5c'] ?? null;

        if ($x5c === null) {
            return [];
        }

        if (! is_array($x5c) || $x5c === []) {
            throw InvalidAttestation::malformedStatement('packed', 'x5c must be a non-empty array of DER certificates');
        }

        $certificates = [];

        foreach ($x5c as $certificate) {
            if (! is_string($certificate) || $certificate === '') {
                throw InvalidAttestation::malformedStatement('packed', 'every x5c entry must be a DER byte string');
            }

            $certificates[] = $certificate;
        }

        return $certificates;
    }
}
