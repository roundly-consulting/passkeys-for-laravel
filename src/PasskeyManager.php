<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Passkeys\Actions\GenerateAuthenticationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\VerifyAuthenticationAction;
use RoundlyConsulting\Passkeys\Attestation\AttestationVerifierRegistry;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\Contracts\PasskeyService;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationExpectation;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * The real {@see PasskeyService}, bound as the `Passkeys` facade root. Every method
 * resolves its action from the container, so a host override of an action applies.
 */
final readonly class PasskeyManager implements PasskeyService
{
    public function __construct(
        private Container $container,
    ) {}

    public function for(Model&HasPasskeys $user): UserPasskeys
    {
        return new UserPasskeys($this->container, $user);
    }

    public function authenticationOptions(?AuthenticationOptionsOverrides $overrides = null): RequestOptionsData
    {
        return $this->container->make(GenerateAuthenticationOptionsAction::class)->execute(null, $overrides);
    }

    public function authenticate(AuthenticationResponseData $response, ?AuthenticationExpectation $expect = null): Passkey
    {
        return $this->container->make(VerifyAuthenticationAction::class)->execute($response, $expect);
    }

    public function attestationFormats(): array
    {
        return $this->container->make(AttestationVerifierRegistry::class)->formats();
    }
}
