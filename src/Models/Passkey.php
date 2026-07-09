<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\Eloquent\SoftDeletes;
use RoundlyConsulting\Passkeys\Database\Factories\PasskeyFactory;

/**
 * A stored WebAuthn credential (passkey).
 *
 * @property int $id
 * @property string $authenticatable_type
 * @property int|string $authenticatable_id
 * @property string $credential_id
 * @property string $public_key
 * @property string $user_handle
 * @property list<string> $transports
 * @property string|null $aaguid
 * @property int $sign_count
 * @property string|null $name
 * @property string|null $attestation_format
 * @property bool $backup_eligible
 * @property bool $backup_state
 * @property CarbonInterface|null $last_used_at
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 * @property CarbonInterface|null $deleted_at
 * @property-read Model $authenticatable
 */
final class Passkey extends Model
{
    /** @use HasFactory<PasskeyFactory> */
    use HasFactory;

    use SoftDeletes;

    protected $guarded = [];

    public function getTable(): string
    {
        $table = config('passkeys.table');

        return is_string($table) ? $table : 'passkeys';
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * @param  Builder<Passkey>  $query
     * @return Builder<Passkey>
     */
    public function scopeForCredentialId(Builder $query, string $credentialId): Builder
    {
        return $query->where('credential_id', $credentialId);
    }

    /**
     * @param  Builder<Passkey>  $query
     * @return Builder<Passkey>
     */
    public function scopeForUserHandle(Builder $query, string $userHandle): Builder
    {
        return $query->where('user_handle', $userHandle);
    }

    public function touchUsage(int $signCount): void
    {
        $this->forceFill([
            'sign_count' => $signCount,
            'last_used_at' => now(),
        ])->save();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'transports' => 'array',
            'sign_count' => 'integer',
            'backup_eligible' => 'boolean',
            'backup_state' => 'boolean',
            'last_used_at' => 'datetime',
        ];
    }

    protected static function newFactory(): PasskeyFactory
    {
        return PasskeyFactory::new();
    }
}
