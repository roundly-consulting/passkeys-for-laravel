<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Concerns;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Random\Bytes;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\Contracts\PasskeyService;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\PasskeyModel;
use RoundlyConsulting\Passkeys\Support\StrictConfig;
use RoundlyConsulting\Passkeys\Support\UserHandleColumn;

/**
 * A drop-in implementation of the HasPasskeys contract.
 *
 * The opaque user handle is generated lazily and persisted to a host-owned
 * column (config `passkeys.user.handle_column`, default `passkey_user_handle`);
 * create it with the `$table->passkeyUserHandle()` Blueprint macro.
 * The account name / display name default to the model's `email` / `name`
 * attributes and can be repointed via config or overridden per model. Every
 * ceremony and count delegates to `Passkeys::for($this)`, so `Passkeys::fake()`
 * sees it.
 *
 * @mixin Model
 *
 * @phpstan-require-extends Model
 *
 * @phpstan-require-implements HasPasskeys
 */
trait InteractsWithPasskeys
{
    /**
     * @return MorphMany<Passkey, $this>
     */
    public function passkeys(): MorphMany
    {
        return $this->morphMany(PasskeyModel::class(), 'authenticatable');
    }

    /**
     * Whether this account has at least one active (non-revoked) passkey — e.g. to
     * offer a passkey second factor only to accounts that can complete it.
     */
    public function hasPasskeys(): bool
    {
        return $this->passkeyService()->for($this)->exists();
    }

    /**
     * How many active (non-revoked) passkeys this account holds.
     */
    public function passkeyCount(): int
    {
        return $this->passkeyService()->for($this)->count();
    }

    /**
     * Build creation options for this user's registration ceremony.
     */
    public function passkeyRegistrationOptions(?RegistrationOptionsOverrides $overrides = null): CreationOptionsData
    {
        return $this->passkeyService()->for($this)->registrationOptions($overrides);
    }

    /**
     * Verify a registration response and store the credential for this user.
     */
    public function registerPasskey(RegistrationResponseData $response, ?string $name = null): Passkey
    {
        return $this->passkeyService()->for($this)->register($response, $name);
    }

    /**
     * Build request options scoped to this user's stored credentials. The ceremony
     * is bound to this user: only one of the offered credentials can complete it.
     */
    public function passkeyAuthenticationOptions(?AuthenticationOptionsOverrides $overrides = null): RequestOptionsData
    {
        return $this->passkeyService()->for($this)->authenticationOptions($overrides);
    }

    /**
     * The opaque user handle — base64url of `passkeys.user.handle_bytes` random
     * bytes — generated once, on first use (registration or authentication
     * options), and persisted to the host-owned handle column.
     *
     * The write is surgical: only the handle column is updated, so any unsaved
     * edit on the model stays unsaved, and the model is not re-saved. An UNSAVED
     * model is never inserted — the handle is only set on it, and its own save
     * persists it (which is how an eager `creating` observer works). The write
     * only fills an EMPTY column, so under two concurrent first-time requests the
     * first handle stored wins and both requests return it.
     */
    public function passkeyUserHandle(): string
    {
        $column = UserHandleColumn::name();
        $existing = $this->getAttribute($column);

        if (is_string($existing) && $existing !== '') {
            return $existing;
        }

        // 16–64 bytes: WebAuthn caps a user handle at 64; fewer than 16 is guessable.
        $bytes = StrictConfig::integer('user.handle_bytes', config('passkeys.user.handle_bytes'), 32, min: 16, max: 64);
        $handle = Base64Url::encode(Bytes::generate($bytes));

        if (! $this->exists) {
            $this->setAttribute($column, $handle);

            return $handle;
        }

        $row = $this->newQueryWithoutScopes()->whereKey($this->getKey());

        $filled = (clone $row)
            ->where(static fn (Builder $query): Builder => $query->whereNull($column)->orWhere($column, ''))
            ->toBase()
            ->update([$column => $handle]);

        if ($filled === 0) {
            $stored = $row->value($column);
            $handle = is_string($stored) && $stored !== '' ? $stored : $handle;
        }

        $this->setAttribute($column, $handle);
        $this->syncOriginalAttribute($column);

        return $handle;
    }

    public function passkeyUserName(): string
    {
        $attribute = StrictConfig::string('user.name_attribute', config('passkeys.user.name_attribute'), 'email');

        return (string) ($this->getAttribute($attribute) ?? $this->getKey());
    }

    public function passkeyDisplayName(): string
    {
        $attribute = StrictConfig::string('user.display_name_attribute', config('passkeys.user.display_name_attribute'), 'name');

        return (string) ($this->getAttribute($attribute) ?? $this->passkeyUserName());
    }

    private function passkeyService(): PasskeyService
    {
        return app(PasskeyService::class);
    }
}
