<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

final class ChallengeMismatch extends PasskeyException
{
    public static function make(): self
    {
        return new self(self::trans('challenge_mismatch'));
    }

    public static function userHandle(): self
    {
        return new self(self::trans('challenge_user_mismatch'));
    }

    public static function ceremonyType(): self
    {
        return new self(self::trans('challenge_ceremony_type'));
    }
}
