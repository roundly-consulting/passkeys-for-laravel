<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\PasskeyModel;

/**
 * A host's own HasPasskeys implementation — no shipped concern, its handle kept in a
 * column of its own choosing — so the package can only learn the handle through the
 * contract.
 *
 * @property int $id
 * @property string|null $name
 * @property string|null $email
 * @property string|null $opaque_handle
 */
final class ContractOwner extends Model implements HasPasskeys
{
    protected $table = 'contract_owners';

    protected $guarded = [];

    public function passkeyUserHandle(): string
    {
        return (string) $this->getAttribute('opaque_handle');
    }

    public function passkeyUserName(): string
    {
        return (string) $this->getAttribute('email');
    }

    public function passkeyDisplayName(): string
    {
        return (string) $this->getAttribute('name');
    }

    /**
     * @return MorphMany<Passkey, $this>
     */
    public function passkeys(): MorphMany
    {
        return $this->morphMany(PasskeyModel::class(), 'authenticatable');
    }
}
