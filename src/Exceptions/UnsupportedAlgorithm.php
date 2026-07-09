<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

final class UnsupportedAlgorithm extends PasskeyException
{
    public static function forId(int $alg): self
    {
        return new self(self::trans('unsupported_algorithm').' ('.$alg.')');
    }
}
