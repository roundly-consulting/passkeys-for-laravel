<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys;

use RoundlyConsulting\Passkeys\Actions\GenerateAuthenticationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\GenerateRegistrationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\VerifyAuthenticationAction;
use RoundlyConsulting\Passkeys\Actions\VerifyRegistrationAction;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * The one-call entry point behind the Passkeys facade. Composes the four ceremony
 * actions so a host performs the common flow in a single expressive call each.
 */
final class PasskeyManager
{
    public function __construct(
        private readonly GenerateRegistrationOptionsAction $registrationOptions,
        private readonly VerifyRegistrationAction $verifyRegistration,
        private readonly GenerateAuthenticationOptionsAction $authenticationOptions,
        private readonly VerifyAuthenticationAction $verifyAuthentication,
    ) {}

    public function registrationOptions(HasPasskeys $user, ?RegistrationOptionsOverrides $overrides = null): CreationOptionsData
    {
        return $this->registrationOptions->execute($user, $overrides);
    }

    public function register(HasPasskeys $user, RegistrationResponseData $response): Passkey
    {
        return $this->verifyRegistration->execute($user, $response);
    }

    public function authenticationOptions(?HasPasskeys $user = null): RequestOptionsData
    {
        return $this->authenticationOptions->execute($user);
    }

    public function authenticate(AuthenticationResponseData $response): Passkey
    {
        return $this->verifyAuthentication->execute($response);
    }
}
