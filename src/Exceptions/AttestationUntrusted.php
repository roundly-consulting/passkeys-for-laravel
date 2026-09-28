<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

/**
 * The attestation statement is internally sound, and POLICY refused it: the
 * chain reaches no configured anchor, no anchor is configured at all, the tier
 * does not accept self-attestation, the chain is not a valid certification path
 * (unlinked, or signed by a certificate that is not a CA / exceeds a
 * pathLenConstraint), a certificate is outside its validity window, or the
 * AAGUID is not allow-listed.
 *
 * Every message names the format, the offending value, and — where the fix is
 * configuration — the exact config key to set.
 */
final class AttestationUntrusted extends PasskeyException
{
    public static function rootNotAnchored(string $format, string $rootSubject, string $fingerprint, string $rootIssuer): self
    {
        return new self(self::trans('attestation_root_not_anchored', [
            'format' => $format,
            'subject' => $rootSubject,
            'fingerprint' => substr($fingerprint, 0, 16),
            'issuer' => $rootIssuer,
        ]));
    }

    public static function noAnchorsConfigured(string $format, string $issuer): self
    {
        return new self(self::trans('attestation_no_anchors', ['format' => $format, 'issuer' => $issuer]));
    }

    public static function selfAttestationRejected(string $format): self
    {
        return new self(self::trans('attestation_self_rejected', ['format' => $format]));
    }

    public static function chainNotLinked(string $format): self
    {
        return new self(self::trans('attestation_chain_not_linked', ['format' => $format]));
    }

    /**
     * A certificate signed another one in the chain without being allowed to:
     * no `CA:TRUE`, or a keyUsage without keyCertSign (RFC 5280 §6.1.4).
     */
    public static function issuerNotCertificateAuthority(string $format, string $subject): self
    {
        return new self(self::trans('attestation_issuer_not_ca', ['format' => $format, 'subject' => $subject]));
    }

    /** A CA's basicConstraints pathLenConstraint is shorter than the chain below it. */
    public static function pathLengthExceeded(string $format, string $subject, int $limit): self
    {
        return new self(self::trans('attestation_path_length_exceeded', [
            'format' => $format,
            'subject' => $subject,
            'limit' => (string) $limit,
        ]));
    }

    /** Deliberately NOT a signature error — a lapsed batch cert is a date fact. */
    public static function certificateExpired(string $subject, string $notAfter, int $leeway): self
    {
        return new self(self::trans('attestation_certificate_expired', [
            'subject' => $subject,
            'not_after' => $notAfter,
            'leeway' => (string) $leeway,
        ]));
    }

    public static function certificateNotYetValid(string $subject, string $notBefore, int $leeway): self
    {
        return new self(self::trans('attestation_certificate_not_yet_valid', [
            'subject' => $subject,
            'not_before' => $notBefore,
            'leeway' => (string) $leeway,
        ]));
    }

    public static function aaguidNotAllowed(?string $aaguid): self
    {
        return new self(self::trans('attestation_aaguid_not_allowed', [
            'aaguid' => $aaguid ?? '(none)',
        ]));
    }
}
