<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

/**
 * The trust policy demands an attestation statement and the authenticator sent
 * none. Almost always a conveyance problem: the ceremony asked for `none`.
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
