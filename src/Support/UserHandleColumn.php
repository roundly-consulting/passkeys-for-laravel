<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Support;

/**
 * The one reader of `passkeys.user.handle_column` — the host-owned column that holds
 * each account's opaque passkey user handle. The concern that reads and writes the
 * handle and the `passkeyUserHandle()` Blueprint macro that creates the column both
 * resolve the name here, so they can never disagree.
 */
final class UserHandleColumn
{
    public const DEFAULT = 'passkey_user_handle';

    public static function name(): string
    {
        return StrictConfig::string('user.handle_column', config('passkeys.user.handle_column'), self::DEFAULT);
    }
}
