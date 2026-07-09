<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

final class OriginMismatch extends PasskeyException
{
    public static function make(): self
    {
        return new self(self::trans('origin_mismatch'));
    }

    public static function crossOrigin(): self
    {
        return new self(self::trans('cross_origin_forbidden'));
    }
}
