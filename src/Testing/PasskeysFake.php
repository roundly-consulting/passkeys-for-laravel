<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Testing;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Cose\CoseAlgorithm;
use RoundlyConsulting\Passkeys\Attestation\AttestationVerifierRegistry;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\Contracts\PasskeyService;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationExpectation;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyAssertionFailed;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\PasskeyModel;
use RoundlyConsulting\Passkeys\UserPasskeys;

/**
 * A first-class, no-crypto testing double for {@see PasskeyService}, swapped in by
 * Passkeys::fake(). It performs NO CBOR/COSE decode, NO signature verification,
 * and NO challenge check — ceremony outcomes are programmable and every
 * register() / authenticate() is recorded so a host can assert its passkey
 * enrolment and login flow without reproducing authenticator crypto.
 *
 * `rename()` / `revoke()` run the real, ownership-checked actions (writes and
 * events included) and are recorded once they succeed. Reads (`all`, `find`,
 * `count`, `exists`) go to the database. Calls through the `InteractsWithPasskeys`
 * verbs are seen too — they route through `Passkeys::for($this)`.
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
 *
 * $this->deleteJson("/passkeys/{$passkey->id}")->assertNoContent();
 * $fake->assertRevoked($passkey);
 * ```
 */
final class PasskeysFake implements PasskeyService
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
     * @var list<array{passkey: Passkey, name: string}>
     */
    private array $renames = [];

    /** @var list<Passkey> */
    private array $revocations = [];

    public function __construct(
        private readonly Container $container,
    ) {}

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
     * Make authenticate() return this exact credential — refused, like the real
     * service, once it is revoked or when it was never saved.
     */
    public function authenticatesAs(Passkey $passkey): self
    {
        $this->authenticatesAs = $passkey;
        $this->acceptsAuthentication = true;

        return $this;
    }

    public function for(Model&HasPasskeys $user): UserPasskeys
    {
        return new RecordingUserPasskeys($this, $this->container, $user);
    }

    public function authenticationOptions(?AuthenticationOptionsOverrides $overrides = null): RequestOptionsData
    {
        return $this->fakeAuthenticationOptions($overrides);
    }

    /**
     * An expectation is honoured exactly as the real verifier does: a credential of
     * the wrong owner is a recorded failure with the uniform not-found error.
     */
    public function authenticate(AuthenticationResponseData $response, ?AuthenticationExpectation $expect = null): Passkey
    {
        return $this->fakeAuthenticate($expect);
    }

    /**
     * The real registry's formats — a pure read of the container binding.
     *
     * @return list<string>
     */
    public function attestationFormats(): array
    {
        return $this->container->make(AttestationVerifierRegistry::class)->formats();
    }

    /**
     * Canned creation options for `for($user)->registrationOptions()`.
     *
     * @internal called by the recording handle
     */
    public function fakeRegistrationOptions(HasPasskeys $user, ?RegistrationOptionsOverrides $overrides = null): CreationOptionsData
    {
        return new CreationOptionsData(
            ceremonyId: self::CANNED_CEREMONY_ID,
            rpId: 'localhost',
            rpName: 'Fake',
            userHandle: self::rawUserHandle($user),
            userName: $user->passkeyUserName(),
            userDisplayName: $user->passkeyDisplayName(),
            challenge: self::CANNED_CHALLENGE,
            algorithms: [CoseAlgorithm::ES256->value],
            timeoutMs: 60_000,
            attestation: $overrides->attestation ?? AttestationConveyance::None,
            userVerification: $overrides->userVerification ?? UserVerification::Required,
        );
    }

    /**
     * `CreationOptionsData::$userHandle` is the RAW handle (it serialises it to
     * base64url itself), so the stored handle is decoded exactly as the real
     * service decodes it — including refusing a malformed one.
     *
     * @throws InvalidClientData
     */
    private static function rawUserHandle(HasPasskeys $user): string
    {
        try {
            return Base64Url::decode($user->passkeyUserHandle());
        } catch (InvalidEncodingException) {
            throw InvalidClientData::malformed();
        }
    }

    /**
     * Persist a factory credential for `for($user)->register()`, recorded — or
     * throw the programmed exception.
     *
     * @internal called by the recording handle
     */
    public function fakeRegister(Model&HasPasskeys $user, ?string $name = null): Passkey
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

    /**
     * Canned request options for both the flat and the scoped ceremony.
     *
     * @internal called by the recording handle
     */
    public function fakeAuthenticationOptions(?AuthenticationOptionsOverrides $overrides = null): RequestOptionsData
    {
        return new RequestOptionsData(
            ceremonyId: self::CANNED_CEREMONY_ID,
            rpId: 'localhost',
            challenge: self::CANNED_CHALLENGE,
            timeoutMs: $overrides->timeoutMs ?? 60_000,
            userVerification: $overrides->userVerification ?? UserVerification::Required,
        );
    }

    /**
     * The programmed authentication outcome, recorded.
     *
     * @internal called by the recording handle
     */
    public function fakeAuthenticate(?AuthenticationExpectation $expect = null): Passkey
    {
        $passkey = $this->acceptsAuthentication
            ? $this->authenticatesAs ?? $this->lastRegisteredPasskey()
            : null;

        if ($passkey === null || ! self::isActive($passkey) || ($expect !== null && ! $expect->matches($passkey))) {
            $this->authentications[] = ['passkey' => null, 'success' => false];

            throw CredentialNotFound::make();
        }

        $this->authentications[] = ['passkey' => $passkey, 'success' => true];

        return $passkey;
    }

    /**
     * @internal called by the recording handle
     */
    public function recordRenamed(Passkey $passkey, string $name): void
    {
        $this->renames[] = ['passkey' => $passkey, 'name' => $name];
    }

    /**
     * @internal called by the recording handle
     */
    public function recordRevoked(Passkey $passkey): void
    {
        $this->revocations[] = $passkey;
    }

    /**
     * A passkey was renamed — this one, and/or to this name, when given.
     */
    public function assertRenamed(?Passkey $passkey = null, ?string $name = null): void
    {
        foreach ($this->renames as $rename) {
            if (($passkey === null || $rename['passkey']->is($passkey)) && ($name === null || $rename['name'] === $name)) {
                return;
            }
        }

        throw PasskeyAssertionFailed::make('Expected a matching passkey rename, but none was recorded.');
    }

    public function assertNothingRenamed(): void
    {
        if ($this->renames !== []) {
            $count = count($this->renames);

            throw PasskeyAssertionFailed::make("Expected no renames, but {$count} were recorded.");
        }
    }

    /**
     * A passkey was revoked — this one, when given.
     */
    public function assertRevoked(?Passkey $passkey = null): void
    {
        foreach ($this->revocations as $revoked) {
            if ($passkey === null || $revoked->is($passkey)) {
                return;
            }
        }

        throw PasskeyAssertionFailed::make('Expected a matching passkey revocation, but none was recorded.');
    }

    public function assertNothingRevoked(): void
    {
        if ($this->revocations !== []) {
            $count = count($this->revocations);

            throw PasskeyAssertionFailed::make("Expected no revocations, but {$count} were recorded.");
        }
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

    /**
     * Still stored and not revoked — re-read through the configured model, as the real
     * verifier locates a credential, so a passkey revoked (or never saved) since it was
     * registered or handed to authenticatesAs() is refused.
     */
    private static function isActive(Passkey $passkey): bool
    {
        return $passkey->exists && PasskeyModel::query()->whereKey($passkey->getKey())->exists();
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
