<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Facades;

use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\Passkeys\PasskeyManager;

/**
 * @method static \RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData registrationOptions(\RoundlyConsulting\Passkeys\Contracts\HasPasskeys $user, ?\RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides $overrides = null)
 * @method static \RoundlyConsulting\Passkeys\Models\Passkey register(\RoundlyConsulting\Passkeys\Contracts\HasPasskeys $user, \RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData $response)
 * @method static \RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData authenticationOptions(?\RoundlyConsulting\Passkeys\Contracts\HasPasskeys $user = null)
 * @method static \RoundlyConsulting\Passkeys\Models\Passkey authenticate(\RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData $response)
 *
 * @see PasskeyManager
 */
final class Passkeys extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return PasskeyManager::class;
    }
}
