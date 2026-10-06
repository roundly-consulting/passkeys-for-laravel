<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Support;

use Illuminate\Database\Eloquent\Model;

/**
 * An abstract account base a host might leave a stored owner type pointing at: it is a
 * model, but no owner can ever be an instance of it.
 */
abstract class AbstractOwner extends Model
{
    protected $table = 'users';

    protected $guarded = [];
}
