<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\Eloquent\SoftDeletes;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Passkeys\Database\Factories\PasskeyFactory;
use RoundlyConsulting\Passkeys\Support\PasskeyModel;
use RoundlyConsulting\Passkeys\Support\StrictConfig;

/**
 * A stored WebAuthn credential (passkey).
 *
 * @property int $id
 * @property string $authenticatable_type
 * @property int|string $authenticatable_id
 * @property string $credential_id
 * @property string $credential_id_hash
 * @property string $public_key
 * @property string $user_handle
 * @property list<string> $transports
 * @property string|null $aaguid
 * @property int $sign_count
 * @property string|null $name
 * @property string|null $attestation_format
 * @property string|null $attestation_type
 * @property bool $backup_eligible
 * @property bool $backup_state
 * @property CarbonInterface|null $last_used_at
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 * @property CarbonInterface|null $deleted_at
 * @property-read Model $authenticatable
 *
 * Not `final`: `passkeys.model` documents pointing the package at a subclass, and a
 * `final` model makes that seam impossible to use. Resolve it through
 * {@see PasskeyModel}, never by naming this class.
 */
class Passkey extends Model
{
    /** @use HasFactory<PasskeyFactory> */
    use HasFactory;

    use SoftDeletes;

    protected $guarded = [];

    /**
     * Hidden by default so a naive ->toArray()/->toJson() never leaks the COSE
     * key material, the discoverable-login handle, or the internal lookup keys.
     * Use PasskeyResource for an explicit, display-safe payload.
     *
     * @var list<string>
     */
    protected $hidden = [
        'public_key',
        'user_handle',
        'credential_id',
        'credential_id_hash',
    ];

    /**
     * Deterministic lookup key for a (potentially long) base64url credential id,
     * so the unique index stays within every database's key-length limit.
     *
     * crypto's SHA-256 digest is byte-for-byte the hex digest this column has
     * always held — an index built before this package used crypto still matches.
     */
    public static function hashCredentialId(string $credentialId): string
    {
        return (new Digest)->hex($credentialId);
    }

    public function getTable(): string
    {
        return StrictConfig::string('table', config('passkeys.table'), 'passkeys');
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
        return $query->where('credential_id_hash', self::hashCredentialId($credentialId));
    }

    /**
     * @param  Builder<Passkey>  $query
     * @return Builder<Passkey>
     */
    public function scopeForUserHandle(Builder $query, string $userHandle): Builder
    {
        return $query->where('user_handle', $userHandle);
    }

    /**
     * Credentials of exactly this owner — its morph type and key — e.g. to list one
     * account's passkeys from a context that only holds the owner model.
     *
     * @param  Builder<Passkey>  $query
     * @return Builder<Passkey>
     */
    public function scopeOwnedBy(Builder $query, Model $owner): Builder
    {
        return $query
            ->where('authenticatable_type', $owner->getMorphClass())
            ->where('authenticatable_id', $owner->getKey());
    }

    /**
     * Move the stored counter FORWARD to $signCount, record the assertion's
     * backup state (BS — current state, WebAuthn L3 §7.2 step 26) and stamp
     * `last_used_at`, in one conditional UPDATE (`… WHERE sign_count < ?`). The database decides, not
     * a comparison made earlier in PHP: two concurrent assertions can never both
     * advance past each other, and a lower counter never overwrites a higher one.
     * A counterless authenticator (a static 0) "advances" only while the stored
     * counter is still 0.
     *
     * Returns false — with the model reloaded, so `sign_count` is what is stored
     * NOW — when the counter did not move: a regression, a concurrent assertion
     * that got there first, or a credential revoked in the meantime (`trashed()`).
     */
    public function advanceSignCount(int $signCount, bool $backupState): bool
    {
        $values = $this->usageStamp($backupState, ['sign_count' => $signCount]);

        $query = $this->newQuery()->whereKey($this->getKey());

        $query = $signCount === 0
            ? $query->where('sign_count', 0)
            : $query->where('sign_count', '<', $signCount);

        if ($query->update($values) !== 1) {
            $this->refresh();

            return false;
        }

        $this->forceFill($values)->syncOriginalAttributes(array_keys($values));

        return true;
    }

    /**
     * Record the backup state and stamp `last_used_at` WITHOUT moving the counter
     * — an assertion accepted despite a regression (the `flag` policy). Nothing
     * else is written, so unrelated unsaved edits on the model stay unsaved.
     */
    public function recordUsage(bool $backupState): void
    {
        $values = $this->usageStamp($backupState, []);

        $this->newQuery()->whereKey($this->getKey())->update($values);

        $this->forceFill($values)->syncOriginalAttributes(array_keys($values));
    }

    /**
     * @param  array<string, mixed>  $values
     * @return array<string, mixed>
     */
    private function usageStamp(bool $backupState, array $values): array
    {
        $now = $this->freshTimestamp();
        $values['backup_state'] = $backupState;
        $values['last_used_at'] = $now;

        $updatedAt = $this->getUpdatedAtColumn();

        if ($this->usesTimestamps() && $updatedAt !== null) {
            $values[$updatedAt] = $now;
        }

        return $values;
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
