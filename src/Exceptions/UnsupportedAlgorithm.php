<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

use Throwable;

final class UnsupportedAlgorithm extends PasskeyException
{
    public static function forId(int $alg): self
    {
        return new self(self::trans('unsupported_algorithm').' ('.$alg.')');
    }

    /**
     * The algorithm was rejected by the crypto layer (unknown COSE identifier,
     * key type or curve, or EdDSA without ext-sodium).
     *
     * @param  string  $reason  the crypto layer's own, untranslated account — kept for
     *                          logs ({@see context()}), never in the localised message
     * @param  Throwable|null  $previous  the lower-level exception behind it
     */
    public static function because(string $reason, ?Throwable $previous = null): self
    {
        return (new self(self::trans('unsupported_algorithm'), 0, $previous))->withReason($reason);
    }
}
