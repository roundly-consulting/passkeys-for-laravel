<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

final class ChallengeExpired extends PasskeyException
{
    public static function make(): self
    {
        return new self(self::trans('challenge_expired'));
    }
}
