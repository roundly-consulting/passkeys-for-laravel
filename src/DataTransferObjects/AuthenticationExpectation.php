<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\Exceptions\InvalidExpectation;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * Who the caller expects the asserted credential to belong to. Checked right after
 * the credential is located — before the challenge is consumed and before any write
 * — so a credential of the wrong owner type (another guard's model) or of another
 * account is refused with the same uniform not-found error as an unknown one, and
 * the legitimate owner can still finish the ceremony.
 */
final readonly class AuthenticationExpectation
{
    private function __construct(
        public string $ownerType,
        public int|string|null $ownerKey,
    ) {}

    /**
     * Any owner of this morph type, e.g. `(new Client)->getMorphClass()`.
     */
    public static function ownerType(string $morphClass): self
    {
        return new self($morphClass, null);
    }

    /**
     * Exactly this owner — its morph type and key.
     *
     * @throws InvalidExpectation when the owner has not been persisted
     */
    public static function owner(Model&HasPasskeys $owner): self
    {
        $key = $owner->getKey();

        // An unsaved owner has no key; silently degrading to a type-only check would
        // widen the expectation to every account of that type.
        if (! is_int($key) && ! is_string($key)) {
            throw InvalidExpectation::unsavedOwner();
        }

        return new self($owner->getMorphClass(), $key);
    }

    public function matches(Passkey $passkey): bool
    {
        if ($passkey->authenticatable_type !== $this->ownerType) {
            return false;
        }

        return $this->ownerKey === null
            || (string) $passkey->authenticatable_id === (string) $this->ownerKey;
    }
}
