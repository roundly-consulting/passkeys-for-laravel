<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

/**
 * The authenticator presented an attestation format this relying party has no
 * verifier for, while the trust policy demands the statement be verified.
 */
final class UnsupportedAttestationFormat extends PasskeyException
{
    /**
     * @param  list<string>  $supported
     */
    public static function forFormat(string $format, array $supported): self
    {
        return new self(self::trans('unsupported_attestation_format', [
            'format' => $format,
            'supported' => implode(', ', $supported),
        ]));
    }
}
