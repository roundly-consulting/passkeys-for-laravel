<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

/**
 * Thrown for every authentication miss — unknown credential id, a userHandle
 * that does not match the stored one, a soft-deleted credential. The message is
 * deliberately uniform so an attacker cannot enumerate registered users.
 */
final class CredentialNotFound extends PasskeyException
{
    public static function make(): self
    {
        return new self(self::trans('credential_not_found'));
    }
}
