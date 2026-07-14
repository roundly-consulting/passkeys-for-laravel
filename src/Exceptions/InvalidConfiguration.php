<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

final class InvalidConfiguration extends PasskeyException
{
    public static function missingRpId(): self
    {
        return new self(self::trans('missing_rp_id'));
    }

    public static function emptyOrigins(): self
    {
        return new self(self::trans('empty_origins'));
    }

    public static function unsupportedAlgorithm(int $alg): self
    {
        return new self(self::trans('unsupported_configured_algorithm', ['alg' => (string) $alg]));
    }

    public static function unsupportedAttestationTrust(string $trust): self
    {
        return new self(self::trans('unsupported_attestation_trust', ['trust' => $trust]));
    }
}
