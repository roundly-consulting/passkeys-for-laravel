<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Facades;

use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\Passkeys\Contracts\PasskeyService;
use RoundlyConsulting\Passkeys\Testing\FakePasskeys;

/**
 * @method static \RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData registrationOptions(\RoundlyConsulting\Passkeys\Contracts\HasPasskeys $user, ?\RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides $overrides = null)
 * @method static \RoundlyConsulting\Passkeys\Models\Passkey register(\RoundlyConsulting\Passkeys\Contracts\HasPasskeys $user, \RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData $response, ?string $name = null)
 * @method static \RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData authenticationOptions(?\RoundlyConsulting\Passkeys\Contracts\HasPasskeys $user = null, ?\RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationOptionsOverrides $overrides = null)
 * @method static \RoundlyConsulting\Passkeys\Models\Passkey authenticate(\RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData $response, ?\RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationExpectation $expect = null)
 * @method static \RoundlyConsulting\Passkeys\Models\Passkey rename(\RoundlyConsulting\Passkeys\Models\Passkey $passkey, string $name)
 * @method static void revoke(\RoundlyConsulting\Passkeys\Models\Passkey $passkey)
 *
 * @see PasskeyService
 */
final class Passkeys extends Facade
{
    /**
     * Swap the passkey service for a programmable, no-crypto recording fake
     * (bound under the service contract) and return it for assertions.
     */
    public static function fake(): FakePasskeys
    {
        $fake = new FakePasskeys;

        self::swap($fake);
        self::getFacadeApplication()->instance(PasskeyService::class, $fake);

        return $fake;
    }

    protected static function getFacadeAccessor(): string
    {
        return PasskeyService::class;
    }
}
