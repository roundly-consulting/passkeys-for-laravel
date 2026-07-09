<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
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
}
