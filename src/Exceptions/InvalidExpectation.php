<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

/**
 * A programming error in how the host built an AuthenticationExpectation — never
 * a ceremony outcome, so it is not a CredentialNotFound.
 */
final class InvalidExpectation extends PasskeyException
{
    public static function unsavedOwner(): self
    {
        return new self(self::trans('expectation_unsaved_owner'));
    }
}
