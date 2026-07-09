<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

final class InvalidCoseKey extends PasskeyException
{
    public static function make(string $reason): self
    {
        return new self(self::trans('invalid_cose_key').' ('.$reason.')');
    }
}
