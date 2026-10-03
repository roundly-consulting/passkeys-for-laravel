<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Support;

use Illuminate\Database\Eloquent\Builder;
use RoundlyConsulting\PackageToolkit\Support\ModelResolver;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * The single seam through which the package resolves the configured `passkeys.model`.
 *
 * Every read and write of the credential table goes through here, so a host that swaps
 * the model gets it honoured everywhere — the stored credential it receives back from a
 * ceremony is its own class, and the model events it hangs revocation/audit logic on
 * actually fire. Narrows the toolkit's `class-string<Model>` to `class-string<Passkey>`,
 * so no call site needs an inline `@var` override.
 */
final class PasskeyModel
{
    /**
     * The configured passkey model.
     *
     * Absent config resolves the packaged model; anything else must be that model or a subclass
     * of it, or the toolkit's ModelResolver throws InvalidConfigurationException naming the key
     * — a foreign class is never silently replaced.
     *
     * @return class-string<Passkey>
     */
    public static function class(): string
    {
        return ModelResolver::for('passkeys.model', Passkey::class);
    }

    /** @return Builder<Passkey> */
    public static function query(): Builder
    {
        return self::class()::query();
    }
}
