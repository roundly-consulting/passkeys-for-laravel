<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\Contracts\PasskeyService;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\Base64Url;

/**
 * A drop-in implementation of the HasPasskeys contract.
 *
 * The opaque user handle is generated lazily and persisted to a host-owned
 * column (config `passkeys.user.handle_column`, default `passkey_user_handle`).
 * The account name / display name default to the model's `email` / `name`
 * attributes and can be repointed via config or overridden per model.
 *
 * @mixin Model
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
        return $this->morphMany(Passkey::class, 'authenticatable');
    }

    /**
     * Build creation options for this user's registration ceremony.
     */
    public function passkeyRegistrationOptions(?RegistrationOptionsOverrides $overrides = null): CreationOptionsData
    {
        return $this->passkeyService()->registrationOptions($this, $overrides);
    }

    /**
     * Verify a registration response and store the credential for this user.
     */
    public function registerPasskey(RegistrationResponseData $response, ?string $name = null): Passkey
    {
        return $this->passkeyService()->register($this, $response, $name);
    }

    /**
     * Build request options scoped to this user's stored credentials.
     */
    public function passkeyAuthenticationOptions(): RequestOptionsData
    {
        return $this->passkeyService()->authenticationOptions($this);
    }

    public function passkeyUserHandle(): string
    {
        $column = $this->passkeyConfigString('user.handle_column', 'passkey_user_handle');
        $existing = $this->getAttribute($column);

        if (is_string($existing) && $existing !== '') {
            return $existing;
        }

        $bytes = (int) config('passkeys.user.handle_bytes', 32);
        $handle = Base64Url::encode(random_bytes(max($bytes, 16)));

        $this->setAttribute($column, $handle);
        $this->save();

        return $handle;
    }

    public function passkeyUserName(): string
    {
        $attribute = $this->passkeyConfigString('user.name_attribute', 'email');

        return (string) ($this->getAttribute($attribute) ?? $this->getKey());
    }

    public function passkeyDisplayName(): string
    {
        $attribute = $this->passkeyConfigString('user.display_name_attribute', 'name');

        return (string) ($this->getAttribute($attribute) ?? $this->passkeyUserName());
    }

    private function passkeyConfigString(string $key, string $default): string
    {
        $value = config('passkeys.'.$key);

        return is_string($value) && $value !== '' ? $value : $default;
    }

    private function passkeyService(): PasskeyService
    {
        return app(PasskeyService::class);
    }
}
