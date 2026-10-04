<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

use Throwable;

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

    /**
     * WebAuthn L3 §7.2 step 19: backup eligibility is fixed when a credential is
     * created, so an assertion reporting a different BE flag is not that credential.
     */
    public static function backupEligibilityChanged(): self
    {
        return new self(self::trans('backup_eligibility_changed'));
    }

    public static function attestedDataMissing(): self
    {
        return new self(self::trans('attested_data_missing'));
    }

    /**
     * The byte structure failed to parse.
     *
     * @param  string  $reason  the crypto layer's own, untranslated account — kept for
     *                          logs ({@see context()}), never in the localised message
     * @param  Throwable|null  $previous  the lower-level exception behind it
     */
    public static function because(string $reason, ?Throwable $previous = null): self
    {
        return (new self(self::trans('invalid_authenticator_data'), 0, $previous))->withReason($reason);
    }
}
