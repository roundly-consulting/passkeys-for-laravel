<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Contracts;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationExpectation;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\PasskeyManager;
use RoundlyConsulting\Passkeys\UserPasskeys;

/**
 * The public passkey API and the `Passkeys` facade root: `for($user)` for everything
 * scoped to one account, plus the user-less discoverable (usernameless) login
 * ceremony. Inject this contract — `Passkeys::fake()` swaps the container binding,
 * so constructor-injected code sees the fake too. The real implementation is
 * {@see PasskeyManager}.
 */
interface PasskeyService
{
    /**
     * One account's passkeys: register, authenticate, list, rename, revoke.
     */
    public function for(Model&HasPasskeys $user): UserPasskeys;

    /**
     * Request options for a discoverable (usernameless) authentication ceremony —
     * no credential list, any account's passkey can answer it.
     */
    public function authenticationOptions(?AuthenticationOptionsOverrides $overrides = null): RequestOptionsData;

    /**
     * Verify an authentication response and return the resolved credential,
     * optionally holding it to an expected owner type or owner.
     *
     * @throws PasskeyException
     */
    public function authenticate(AuthenticationResponseData $response, ?AuthenticationExpectation $expect = null): Passkey;

    /**
     * The attestation formats this relying party can verify (WebAuthn `fmt` values).
     *
     * @return list<string>
     */
    public function attestationFormats(): array;
}
