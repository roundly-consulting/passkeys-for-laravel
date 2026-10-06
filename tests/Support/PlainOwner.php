<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Support;

use Illuminate\Database\Eloquent\Model;

/**
 * A model that owns passkeys without implementing HasPasskeys — it has no user handle
 * of its own for the package to read or mint. It reuses the host `users` table.
 *
 * @property int $id
 * @property string|null $name
 * @property string|null $email
 * @property string|null $passkey_user_handle
 */
final class PlainOwner extends Model
{
    protected $table = 'users';

    protected $guarded = [];
}
