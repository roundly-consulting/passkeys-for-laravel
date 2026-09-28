<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Passkeys\Actions\GenerateAuthenticationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\GenerateRegistrationOptionsAction;
use RoundlyConsulting\Passkeys\Actions\RenamePasskeyAction;
use RoundlyConsulting\Passkeys\Actions\RevokePasskeyAction;
use RoundlyConsulting\Passkeys\Actions\VerifyAuthenticationAction;
use RoundlyConsulting\Passkeys\Actions\VerifyRegistrationAction;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationExpectation;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * One account's passkeys, returned by `Passkeys::for($user)`. Every ceremony and
 * write resolves its action from the container, so host overrides and
 * `Passkeys::fake()` apply; the `InteractsWithPasskeys` verbs route through here.
 *
 * Scoping is a security boundary: `authenticate()` only accepts this account's
 * credential, and `rename()` / `revoke()` refuse a passkey of any other account
 * (or a revoked one) with the uniform `CredentialNotFound`.
 *
 * Not final: the recording fake extends it.
 */
readonly class UserPasskeys
{
    public function __construct(
        protected Container $container,
        protected Model&HasPasskeys $user,
    ) {}

    public function registrationOptions(?RegistrationOptionsOverrides $overrides = null): CreationOptionsData
    {
        return $this->container->make(GenerateRegistrationOptionsAction::class)->execute($this->user, $overrides);
    }

    /**
     * Verify a registration response and store the credential for this account,
     * optionally under a friendly name.
     *
     * @throws PasskeyException
     */
    public function register(RegistrationResponseData $response, ?string $name = null): Passkey
    {
        return $this->container->make(VerifyRegistrationAction::class)->execute($this->user, $response, $name);
    }

    /**
     * Request options bound to this account: only one of its credentials can
     * complete the ceremony.
     */
    public function authenticationOptions(?AuthenticationOptionsOverrides $overrides = null): RequestOptionsData
    {
        return $this->container->make(GenerateAuthenticationOptionsAction::class)->execute($this->user, $overrides);
    }

    /**
     * Verify an authentication response held to this account
     * (`AuthenticationExpectation::owner($user)`).
     *
     * @throws PasskeyException
     */
    public function authenticate(AuthenticationResponseData $response): Passkey
    {
        return $this->container->make(VerifyAuthenticationAction::class)
            ->execute($response, AuthenticationExpectation::owner($this->user));
    }

    /**
     * This account's active passkeys, newest first.
     *
     * @return Collection<int, Passkey>
     */
    public function all(): Collection
    {
        return $this->user->passkeys()->latest()->latest('id')->get();
    }

    /**
     * One of this account's active passkeys, or null — also for another account's id.
     */
    public function find(int $id): ?Passkey
    {
        return $this->user->passkeys()->whereKey($id)->first();
    }

    public function count(): int
    {
        return $this->user->passkeys()->count();
    }

    public function exists(): bool
    {
        return $this->user->passkeys()->exists();
    }

    /**
     * Rename one of this account's passkeys (cosmetic only — never a verification
     * input) and fire `PasskeyRenamed`.
     *
     * @throws CredentialNotFound when it is not one of this account's active passkeys
     */
    public function rename(Passkey|int $passkey, string $name): Passkey
    {
        return $this->container->make(RenamePasskeyAction::class)->execute($this->owned($passkey), $name);
    }

    /**
     * Revoke (soft-delete) one of this account's passkeys so it can no longer
     * authenticate, and fire `PasskeyRevoked`.
     *
     * @throws CredentialNotFound when it is not one of this account's active passkeys
     */
    public function revoke(Passkey|int $passkey): void
    {
        $this->container->make(RevokePasskeyAction::class)->execute($this->owned($passkey));
    }

    /**
     * The given passkey, once proven to be one of this account's active ones.
     *
     * @throws CredentialNotFound
     */
    protected function owned(Passkey|int $passkey): Passkey
    {
        if (is_int($passkey)) {
            return $this->find($passkey) ?? throw CredentialNotFound::make();
        }

        if (! $this->user->passkeys()->whereKey($passkey->getKey())->exists()) {
            throw CredentialNotFound::make();
        }

        return $passkey;
    }
}
