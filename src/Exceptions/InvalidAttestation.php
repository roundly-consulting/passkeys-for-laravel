<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

/**
 * The attestation statement's MATHS failed: it is malformed, or its signature,
 * algorithm, key binding or certificate shape does not hold.
 *
 * Distinct from {@see AttestationUntrusted}, which is policy refusing a
 * statement that is internally sound. A host can log forgeries (this) separately
 * from configuration refusals (that).
 */
final class InvalidAttestation extends PasskeyException
{
    public static function malformedStatement(string $format, string $reason): self
    {
        return new self(self::trans('attestation_malformed_statement', [
            'format' => $format,
            'reason' => $reason,
        ]));
    }

    public static function signatureMismatch(string $format): self
    {
        return new self(self::trans('attestation_signature_mismatch', ['format' => $format]));
    }

    public static function algorithmMismatch(string $format, int $claimed, int $actual): self
    {
        return new self(self::trans('attestation_algorithm_mismatch', [
            'format' => $format,
            'claimed' => (string) $claimed,
            'actual' => (string) $actual,
        ]));
    }

    public static function aaguidMismatch(): self
    {
        return new self(self::trans('attestation_aaguid_mismatch'));
    }

    /**
     * The attestation certificate certifies a DIFFERENT key than the credential
     * the ceremony is registering — a genuine path lifted onto a foreign key.
     */
    public static function credentialKeyMismatch(string $format): self
    {
        return new self(self::trans('attestation_credential_key_mismatch', ['format' => $format]));
    }

    /**
     * Apple's nonce extension does not hold SHA-256(authData ‖ clientDataHash):
     * the statement was minted for another ceremony, or its inputs were tampered
     * with. Either way it is not a proof about THIS registration.
     */
    public static function appleNonceMismatch(): self
    {
        return new self(self::trans('attestation_apple_nonce_mismatch'));
    }

    /** A §8.2.1-style certificate requirement the leaf does not meet. */
    public static function certificateRequirement(string $format, string $requirement): self
    {
        return new self(self::trans('attestation_certificate_requirement', [
            'format' => $format,
            'requirement' => $requirement,
        ]));
    }

    /** ECDAA was removed from WebAuthn Level 3 and is never accepted. */
    public static function ecdaaUnsupported(string $format): self
    {
        return new self(self::trans('attestation_ecdaa_unsupported', ['format' => $format]));
    }
}
