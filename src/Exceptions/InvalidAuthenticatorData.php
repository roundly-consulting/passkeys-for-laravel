<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

final class InvalidAuthenticatorData extends PasskeyException
{
    public static function make(): self
    {
        return new self(self::trans('invalid_authenticator_data'));
    }

    public static function userPresenceMissing(): self
    {
        return new self(self::trans('user_presence_missing'));
    }

    public static function backupStateInconsistent(): self
    {
        return new self(self::trans('backup_state_inconsistent'));
    }

    public static function attestedDataMissing(): self
    {
        return new self(self::trans('attested_data_missing'));
    }
}
