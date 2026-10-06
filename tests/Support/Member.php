<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use RoundlyConsulting\Passkeys\Concerns\InteractsWithPasskeys;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;

/**
 * An account model that soft-deletes, owning passkeys through the shipped concern — what
 * a host that keeps closed accounts around looks like. Its table is built by the tests
 * that use it.
 *
 * @property int $id
 * @property string|null $name
 * @property string|null $email
 * @property string|null $passkey_user_handle
 */
final class Member extends Model implements HasPasskeys
{
    use InteractsWithPasskeys;
    use SoftDeletes;

    protected $table = 'members';

    protected $guarded = [];
}
