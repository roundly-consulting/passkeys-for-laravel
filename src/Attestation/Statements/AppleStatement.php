<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Attestation\Statements;

use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAttestation;

/**
 * A typed view over an `apple` attestation statement (WebAuthn §8.8).
 *
 * Apple's anonymous attestation carries a certificate path and NOTHING else — no
 * `sig`, no `alg`. The binding to this ceremony is not a signature over the
 * authenticator data but a nonce baked into the credential certificate itself, so
 * the only field to type is `x5c`.
 *
 * Its entries are RAW DER byte strings, as CBOR carries them — never the base64 a
 * JOSE `x5c` header carries.
 */
final readonly class AppleStatement
{
    /**
     * @param  list<string>  $x5c  raw DER certificates, credCert first
     */
    private function __construct(
        public array $x5c,
    ) {}

    /**
     * @throws InvalidAttestation
     */
    public static function fromAttestationObject(AttestationObject $attestation): self
    {
        $x5c = $attestation->statement['x5c'] ?? null;

        if (! is_array($x5c) || $x5c === []) {
            throw InvalidAttestation::malformedStatement('apple', 'x5c_not_list');
        }

        $certificates = [];

        foreach ($x5c as $certificate) {
            if (! is_string($certificate) || $certificate === '') {
                throw InvalidAttestation::malformedStatement('apple', 'x5c_entry_not_bytes');
            }

            $certificates[] = $certificate;
        }

        return new self($certificates);
    }
}
