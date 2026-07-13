<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

/**
 * The attestation statement is internally sound, and POLICY refused it: the
 * chain reaches no configured anchor, no anchor is configured at all, the tier
 * does not accept self-attestation, a certificate is outside its validity
 * window, or the AAGUID is not allow-listed.
 *
 * Every message names the format, the offending value, and — where the fix is
 * configuration — the exact config key to set.
 */
final class AttestationUntrusted extends PasskeyException
{
    public static function rootNotAnchored(string $format, string $rootSubject, string $fingerprint): self
    {
        return new self(self::trans('attestation_root_not_anchored', [
            'format' => $format,
            'subject' => $rootSubject,
            'fingerprint' => substr($fingerprint, 0, 16),
        ]));
    }

    public static function noAnchorsConfigured(string $format): self
    {
        return new self(self::trans('attestation_no_anchors', ['format' => $format]));
    }

    public static function selfAttestationRejected(string $format): self
    {
        return new self(self::trans('attestation_self_rejected', ['format' => $format]));
    }

    public static function chainNotLinked(string $format): self
    {
        return new self(self::trans('attestation_chain_not_linked', ['format' => $format]));
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
