<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

final class RpIdMismatch extends PasskeyException
{
    public static function make(): self
    {
        return new self(self::trans('rp_id_mismatch'));
    }
}
