<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

final class SignCountRegression extends PasskeyException
{
    public static function make(int $stored, int $received): self
    {
        return new self(self::trans('sign_count_regression').' ('.$received.' <= '.$stored.')');
    }
}
