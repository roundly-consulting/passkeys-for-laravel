<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Contracts;

use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * The public passkey ceremony surface behind the Passkeys facade. Extracting the
 * contract lets a host swap the real relying party for a testing double
 * (Passkeys::fake()) without reproducing any authenticator crypto.
 */
interface PasskeyService
{
    /**
     * Build the creation options for a registration ceremony.
     */
    public function registrationOptions(HasPasskeys $user, ?RegistrationOptionsOverrides $overrides = null): CreationOptionsData;

    /**
     * Verify a registration response and persist the credential, optionally under
     * a host-supplied friendly name.
     *
     * @throws PasskeyException
     */
    public function register(HasPasskeys $user, RegistrationResponseData $response, ?string $name = null): Passkey;

    /**
     * Build the request options for an authentication ceremony.
     */
    public function authenticationOptions(?HasPasskeys $user = null): RequestOptionsData;

    /**
     * Verify an authentication response and return the resolved credential.
     *
     * @throws PasskeyException
     */
    public function authenticate(AuthenticationResponseData $response): Passkey;

    /**
     * Rename a stored credential (cosmetic only — never a verification input).
     */
    public function rename(Passkey $passkey, string $name): Passkey;

    /**
     * Revoke (soft-delete) a stored credential so it can no longer authenticate.
     */
    public function revoke(Passkey $passkey): void;
}
