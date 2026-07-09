<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

final class UserVerificationRequired extends PasskeyException
{
    public static function make(): self
    {
        return new self(self::trans('user_verification_required'));
    }
}
