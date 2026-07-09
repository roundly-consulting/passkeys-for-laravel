<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Support;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Passkeys\Concerns\InteractsWithPasskeys;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;

/**
 * @property int $id
 * @property string|null $name
 * @property string|null $email
 * @property string|null $passkey_user_handle
 */
final class User extends Model implements HasPasskeys
{
    use InteractsWithPasskeys;

    protected $table = 'users';

    protected $guarded = [];
}
