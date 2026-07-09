<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Contracts;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * Implemented by any model that can own passkeys. Use the
 * `InteractsWithPasskeys` concern for a ready-made implementation.
 */
interface HasPasskeys
{
    /** An opaque, non-PII, stable per-user handle (base64url of ≥16 random bytes). */
    public function passkeyUserHandle(): string;

    /** The account name shown in the authenticator UI (e.g. email). */
    public function passkeyUserName(): string;

    /** The friendly display name shown in the authenticator UI (e.g. full name). */
    public function passkeyDisplayName(): string;

    /**
     * @return MorphMany<Passkey, covariant Model>
     */
    public function passkeys(): MorphMany;
}
