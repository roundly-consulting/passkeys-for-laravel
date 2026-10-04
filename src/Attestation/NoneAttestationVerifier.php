<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Attestation;

use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\Enums\AttestationType;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAttestation;

/**
 * The `none` format (WebAuthn §8.7): the authenticator attests to nothing.
 *
 * Its whole "maths" is that the statement carries no data — an authenticator
 * stuffing anything into a `none` attStmt is not following the spec. Whether a
 * credential with no attestation may enrol is the gate's ruling, not this
 * verifier's: it reports {@see AttestationType::None} and stops.
 */
final class NoneAttestationVerifier implements AttestationVerifier
{
    public function verify(
        AttestationObject $attestation,
        AuthenticatorData $authenticatorData,
        string $clientDataHash,
    ): AttestationResult {
        if ($attestation->statement !== []) {
            throw InvalidAttestation::malformedStatement('none', 'none_statement_not_empty');
        }

        return AttestationResult::none($attestation->format);
    }
}
