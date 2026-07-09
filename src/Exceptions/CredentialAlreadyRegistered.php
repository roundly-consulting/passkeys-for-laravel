<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

final class CredentialAlreadyRegistered extends PasskeyException
{
    public static function make(): self
    {
        return new self(self::trans('credential_already_registered'));
    }
}
