<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Support;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Passkeys\Concerns\InteractsWithPasskeys;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * The one owner check: whether the account a passkey belongs to still holds it. The
 * real verifier and `Passkeys::fake()` both ask here, so the fake refuses exactly the
 * passkeys production refuses.
 *
 * @internal
 */
final class CredentialOwner
{
    /**
     * The owner must still exist — a soft-deleted one is gone, as Laravel's own user
     * provider sees it — and must still hold the handle the credential was minted
     * for, so an account that reuses a deleted owner's id never inherits its
     * passkeys.
     *
     * The shipped concern's handle is read straight off its column: asking the
     * concern would mint a handle for an account that has none, and a fresh random
     * handle can never match anyway. Any other implementation is asked through the
     * contract. An owner that is not `HasPasskeys` is checked for existence only.
     *
     * An owner type that no longer names a model — a renamed class, a morph alias
     * dropped from the map, the factory's default `user` — is a missing owner: the
     * passkey is refused, never a raw class-not-found `Error`.
     */
    public static function holds(Passkey $passkey): bool
    {
        if (! self::resolvable($passkey)) {
            return false;
        }

        // Not `$passkey->authenticatable`: loading the relation would add the owner
        // to the returned passkey's array/JSON form.
        $owner = $passkey->authenticatable()->getResults();

        if ($owner === null) {
            return false;
        }

        return ! $owner instanceof HasPasskeys || ConstantTime::equals(self::storedHandle($owner), $passkey->user_handle);
    }

    /**
     * Whether the passkey's owner type names an Eloquent model, directly or through
     * the morph map — resolving the relation of one that does not throws.
     */
    private static function resolvable(Passkey $passkey): bool
    {
        $class = $passkey::getActualClassNameForMorph($passkey->authenticatable_type);

        return class_exists($class) && is_subclass_of($class, Model::class);
    }

    private static function storedHandle(Model&HasPasskeys $owner): string
    {
        if (! in_array(InteractsWithPasskeys::class, class_uses_recursive($owner), true)) {
            return $owner->passkeyUserHandle();
        }

        $handle = $owner->getAttribute(UserHandleColumn::name());

        return is_string($handle) ? $handle : '';
    }
}
