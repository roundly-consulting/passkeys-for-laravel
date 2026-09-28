<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Testing;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationExpectation;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\UserPasskeys;

/**
 * The account handle under `Passkeys::fake()`: ceremonies return the fake's
 * programmed, no-crypto outcomes (authentication held to this account, exactly
 * like the real handle); `rename()` / `revoke()` run the real ownership-checked
 * actions and are recorded once they succeed; reads go to the database.
 */
final readonly class RecordingUserPasskeys extends UserPasskeys
{
    public function __construct(
        private PasskeysFake $fake,
        Container $container,
        Model&HasPasskeys $user,
    ) {
        parent::__construct($container, $user);
    }

    public function registrationOptions(?RegistrationOptionsOverrides $overrides = null): CreationOptionsData
    {
        return $this->fake->fakeRegistrationOptions($this->user, $overrides);
    }

    public function register(RegistrationResponseData $response, ?string $name = null): Passkey
    {
        return $this->fake->fakeRegister($this->user, $name);
    }

    public function authenticationOptions(?AuthenticationOptionsOverrides $overrides = null): RequestOptionsData
    {
        return $this->fake->fakeAuthenticationOptions($overrides);
    }

    public function authenticate(AuthenticationResponseData $response): Passkey
    {
        return $this->fake->fakeAuthenticate(AuthenticationExpectation::owner($this->user));
    }

    public function rename(Passkey|int $passkey, string $name): Passkey
    {
        $renamed = parent::rename($passkey, $name);

        $this->fake->recordRenamed($renamed, $name);

        return $renamed;
    }

    public function revoke(Passkey|int $passkey): void
    {
        $owned = $this->owned($passkey);

        parent::revoke($owned);

        $this->fake->recordRevoked($owned);
    }
}
