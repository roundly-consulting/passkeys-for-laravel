<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

final class InvalidClientData extends PasskeyException
{
    public static function wrongType(string $expected): self
    {
        return new self(self::trans('invalid_client_data').' ('.$expected.')');
    }

    public static function malformed(): self
    {
        return new self(self::trans('invalid_client_data'));
    }
}
