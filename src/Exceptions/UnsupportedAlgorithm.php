<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

final class UnsupportedAlgorithm extends PasskeyException
{
    public static function forId(int $alg): self
    {
        return new self(self::trans('unsupported_algorithm').' ('.$alg.')');
    }

    /**
     * The algorithm was rejected by the crypto layer (unknown COSE identifier,
     * key type or curve, or EdDSA without ext-sodium) — the reason is carried
     * through so the cause survives the boundary translation.
     */
    public static function because(string $reason): self
    {
        return new self(self::trans('unsupported_algorithm').' ('.$reason.')');
    }
}
