<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Testing;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\Contracts\PasskeyService;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\CoseAlgorithm;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyAssertionFailed;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * A first-class, no-crypto testing double for {@see PasskeyService}, swapped in by
 * Passkeys::fake(). It performs NO CBOR/COSE decode, NO signature verification,
 * and NO challenge check — outcomes are programmable and every register()/
 * authenticate() call is recorded so a host can assert its passkey enrolment and
 * login flow without reproducing authenticator crypto.
 *
 * Test-only: it lives in runtime autoload purely to follow Laravel's own Fakes
 * pattern, is bound solely via Passkeys::fake(), and must never reach production.
 * Assertions throw a package exception (not a PHPUnit assertion) so it works under
 * any runner.
 *
 * ```php
 * $fake = Passkeys::fake();
 * $this->postJson('/passkeys', ['id' => 'x', 'rawId' => 'x', 'response' => []])->assertCreated();
 * $fake->assertRegisteredFor($user);
 * ```
 */
final class FakePasskeys implements PasskeyService
{
    private const CANNED_CEREMONY_ID = 'fake-ceremony';

    private const CANNED_CHALLENGE = 'ZmFrZS1jaGFsbGVuZ2UtMDAwMDAwMDAwMDAwMDAwMDA';

    private bool $acceptsAuthentication = true;

    private ?PasskeyException $registrationError = null;

    private ?Passkey $authenticatesAs = null;

    /**
     * @var list<array{user: HasPasskeys, passkey: Passkey, name: ?string}>
     */
    private array $registrations = [];

    /**
     * @var list<array{passkey: ?Passkey, success: bool}>
     */
    private array $authentications = [];

    /**
     * Make register() persist a credential again (the default).
     */
    public function acceptRegistration(): self
    {
        $this->registrationError = null;

        return $this;
    }

    /**
     * Make register() throw the given exception instead of persisting.
     */
    public function failRegistrationWith(PasskeyException $exception): self
    {
        $this->registrationError = $exception;

        return $this;
    }

    /**
     * Make authenticate() succeed (the default).
     */
    public function acceptAuthentication(): self
    {
        $this->acceptsAuthentication = true;

        return $this;
    }

    /**
     * Make authenticate() throw CredentialNotFound.
     */
    public function rejectAuthentication(): self
    {
        $this->acceptsAuthentication = false;

        return $this;
    }

    /**
     * Make authenticate() return this exact credential.
     */
    public function authenticatesAs(Passkey $passkey): self
    {
        $this->authenticatesAs = $passkey;
        $this->acceptsAuthentication = true;

        return $this;
    }

    public function registrationOptions(HasPasskeys $user, ?RegistrationOptionsOverrides $overrides = null): CreationOptionsData
    {
        return new CreationOptionsData(
            ceremonyId: self::CANNED_CEREMONY_ID,
            rpId: 'localhost',
            rpName: 'Fake',
            userHandle: $user->passkeyUserHandle(),
            userName: $user->passkeyUserName(),
            userDisplayName: $user->passkeyDisplayName(),
            challenge: self::CANNED_CHALLENGE,
            algorithms: [CoseAlgorithm::ES256->value],
            timeoutMs: 60_000,
            attestation: $overrides->attestation ?? AttestationConveyance::None,
            userVerification: $overrides->userVerification ?? UserVerification::Required,
        );
    }

    public function register(HasPasskeys $user, RegistrationResponseData $response, ?string $name = null): Passkey
    {
        if ($this->registrationError !== null) {
            throw $this->registrationError;
        }

        $passkey = Passkey::factory()->es256()->make([
            'user_handle' => $user->passkeyUserHandle(),
            'name' => $name,
        ]);

        $user->passkeys()->save($passkey);

        $this->registrations[] = ['user' => $user, 'passkey' => $passkey, 'name' => $name];

        return $passkey;
    }

    public function authenticationOptions(?HasPasskeys $user = null): RequestOptionsData
    {
        return new RequestOptionsData(
            ceremonyId: self::CANNED_CEREMONY_ID,
            rpId: 'localhost',
            challenge: self::CANNED_CHALLENGE,
            timeoutMs: 60_000,
            userVerification: UserVerification::Required,
        );
    }

    public function authenticate(AuthenticationResponseData $response): Passkey
    {
        if (! $this->acceptsAuthentication) {
            $this->authentications[] = ['passkey' => null, 'success' => false];

            throw CredentialNotFound::make();
        }

        $passkey = $this->authenticatesAs ?? $this->lastRegisteredPasskey();

        $this->authentications[] = ['passkey' => $passkey, 'success' => true];

        return $passkey;
    }

    public function rename(Passkey $passkey, string $name): Passkey
    {
        $passkey->forceFill(['name' => $name])->save();

        return $passkey;
    }

    public function revoke(Passkey $passkey): void
    {
        $passkey->delete();
    }

    public function assertRegistered(): void
    {
        if ($this->registrations === []) {
            throw PasskeyAssertionFailed::make('Expected at least one registration, but none was recorded.');
        }
    }

    public function assertRegisteredFor(Model $user): void
    {
        foreach ($this->registrations as $registration) {
            if ($this->passkeyBelongsTo($registration['passkey'], $user)) {
                return;
            }
        }

        throw PasskeyAssertionFailed::make('Expected a registration for the given user, but none was recorded.');
    }

    public function assertNothingRegistered(): void
    {
        if ($this->registrations !== []) {
            $count = count($this->registrations);

            throw PasskeyAssertionFailed::make("Expected no registrations, but {$count} were recorded.");
        }
    }

    public function assertAuthenticated(): void
    {
        foreach ($this->authentications as $authentication) {
            if ($authentication['success']) {
                return;
            }
        }

        throw PasskeyAssertionFailed::make('Expected at least one successful authentication, but none succeeded.');
    }

    public function assertAuthenticatedFor(Model $user): void
    {
        foreach ($this->authentications as $authentication) {
            $passkey = $authentication['passkey'];

            if ($authentication['success'] && $passkey !== null && $this->passkeyBelongsTo($passkey, $user)) {
                return;
            }
        }

        throw PasskeyAssertionFailed::make('Expected a successful authentication for the given user, but none was recorded.');
    }

    public function assertAuthenticationFailed(): void
    {
        foreach ($this->authentications as $authentication) {
            if (! $authentication['success']) {
                return;
            }
        }

        throw PasskeyAssertionFailed::make('Expected at least one failed authentication, but none failed.');
    }

    public function assertRegistrationCount(int $count): void
    {
        $actual = count($this->registrations);

        if ($actual !== $count) {
            throw PasskeyAssertionFailed::make("Expected {$count} registration(s), but {$actual} were recorded.");
        }
    }

    public function assertAuthenticationCount(int $count): void
    {
        $actual = count($this->authentications);

        if ($actual !== $count) {
            throw PasskeyAssertionFailed::make("Expected {$count} authentication(s), but {$actual} were recorded.");
        }
    }

    private function passkeyBelongsTo(Passkey $passkey, Model $user): bool
    {
        return $passkey->authenticatable_type === $user->getMorphClass()
            && (string) $passkey->authenticatable_id === (string) $user->getKey();
    }

    private function lastRegisteredPasskey(): Passkey
    {
        $last = end($this->registrations);

        if ($last !== false) {
            return $last['passkey'];
        }

        /** @var Passkey $passkey */
        $passkey = Passkey::factory()->es256()->create();

        return $passkey;
    }
}
