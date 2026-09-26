<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Support;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Passkeys\Concerns\InteractsWithPasskeys;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;

/**
 * A second authenticatable (another guard's model) owning passkeys through the same
 * `authenticatable` morph — what a multi-guard host looks like.
 *
 * @property int $id
 * @property string|null $name
 * @property string|null $email
 * @property string|null $passkey_user_handle
 */
final class Client extends Model implements HasPasskeys
{
    use InteractsWithPasskeys;

    protected $table = 'clients';

    protected $guarded = [];
}
