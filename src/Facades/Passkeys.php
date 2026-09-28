<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Facades;

use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\Passkeys\Contracts\PasskeyService;
use RoundlyConsulting\Passkeys\PasskeyManager;
use RoundlyConsulting\Passkeys\Testing\PasskeysFake;

/**
 * @method static \RoundlyConsulting\Passkeys\UserPasskeys for(\Illuminate\Database\Eloquent\Model&\RoundlyConsulting\Passkeys\Contracts\HasPasskeys $user)
 * @method static \RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData authenticationOptions(?\RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationOptionsOverrides $overrides = null)
 * @method static \RoundlyConsulting\Passkeys\Models\Passkey authenticate(\RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData $response, ?\RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationExpectation $expect = null)
 * @method static list<string> attestationFormats()
 *
 * @see PasskeyService
 * @see PasskeyManager
 */
final class Passkeys extends Facade
{
    /**
     * Swap the passkey service for a programmable, no-crypto recording fake
     * (bound under the service contract) and return it for assertions.
     */
    public static function fake(): PasskeysFake
    {
        $fake = app(PasskeysFake::class);

        self::swap($fake);

        return $fake;
    }

    protected static function getFacadeAccessor(): string
    {
        return PasskeyService::class;
    }
}
