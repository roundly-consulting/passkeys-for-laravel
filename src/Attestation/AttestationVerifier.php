<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Attestation;

use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;

/**
 * Verifies the MATHS of one attestation statement and reports what it proved.
 *
 * A format verifier rules on nothing: it never consults a trust anchor, never
 * reads the trust tier, never looks at the AAGUID allow-list. It answers only
 * "does this statement hold together, and what grade of attestation is that".
 * The policy — anchors, validity dates, tiers, allow-lists — belongs to
 * {@see AttestationGate}, which is what the container binds this interface to.
 *
 * That is the same boundary crypto draws against this package (algorithms there,
 * trust here), redrawn one level down.
 */
interface AttestationVerifier
{
    /**
     * @throws PasskeyException
     */
    public function verify(
        AttestationObject $attestation,
        AuthenticatorData $authenticatorData,
        string $clientDataHash,
    ): AttestationResult;
}
