<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

use Throwable;

final class InvalidCoseKey extends PasskeyException
{
    /**
     * @param  string  $reason  the key loader's own, untranslated account of the failure — kept for
     *                          logs ({@see context()}), never in the localised message
     * @param  Throwable|null  $previous  the lower-level exception behind it
     */
    public static function make(string $reason, ?Throwable $previous = null): self
    {
        return (new self(self::trans('invalid_cose_key'), 0, $previous))->withReason($reason);
    }
}
