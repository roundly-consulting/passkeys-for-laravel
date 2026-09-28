<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Concerns;

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
     * The opaque user handle is generated once and persisted to the host-owned
     * handle column on first use (registration or authentication options). This
     * is a write on a read-shaped call: under two concurrent first-time option
     * requests both may persist a handle (last write wins; the value is random,
     * stable-once-set and non-PII, so the outcome is harmless). Hosts that want
     * to avoid the lazy write entirely can generate the handle eagerly at user
     * creation via an observer/migration — see the README "Preparing your user
     * model" section.
     */
    public function passkeyUserHandle(): string
    {
        $column = UserHandleColumn::name();
        $existing = $this->getAttribute($column);

        if (is_string($existing) && $existing !== '') {
            return $existing;
        }

        $bytes = (int) config('passkeys.user.handle_bytes', 32);
        $handle = Base64Url::encode(Bytes::generate(max($bytes, 16)));

        $this->setAttribute($column, $handle);
        $this->save();

        return $handle;
    }

    public function passkeyUserName(): string
    {
        $attribute = $this->passkeyConfigString('passkeys.user.name_attribute', 'email');

        return (string) ($this->getAttribute($attribute) ?? $this->getKey());
    }

    public function passkeyDisplayName(): string
    {
        $attribute = $this->passkeyConfigString('passkeys.user.display_name_attribute', 'name');

        return (string) ($this->getAttribute($attribute) ?? $this->passkeyUserName());
    }

    /**
     * Callers pass the FULL literal key rather than a suffix concatenated onto 'passkeys.'
     * here. A concatenated key cannot be checked against the shipped config file, which is
     * the exact shape that let shops #18 read a key the package never shipped while its suite
     * stayed green. Naming each key whole makes every read verifiable at its call site.
     */
    private function passkeyConfigString(string $key, string $default): string
    {
        $value = config($key);

        return is_string($value) && $value !== '' ? $value : $default;
    }

    private function passkeyService(): PasskeyService
    {
        return app(PasskeyService::class);
    }
}
