<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

/**
 * The trust policy demands an attestation statement and the authenticator sent
 * none. Usually a synced passkey (iCloud Keychain, Google Password Manager, most
 * password managers), which answers `fmt: none` whatever the ceremony requests.
 * A configured `none` conveyance under a strict tier already fails at boot; a
 * per-call `attestation: None` override is the other way to get here.
 */
final class AttestationRequired extends PasskeyException
{
    public static function statementMissing(string $trust, string $format): self
    {
        return new self(self::trans('attestation_statement_missing', [
            'trust' => $trust,
            'format' => $format,
        ]));
    }
}
