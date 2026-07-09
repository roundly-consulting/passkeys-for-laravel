<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

final class MalformedCbor extends PasskeyException
{
    public static function make(string $reason): self
    {
        return new self(self::trans('malformed_cbor').' ('.$reason.')');
    }
}
