<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Testing;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Passkeys\Attestation\AttestationVerifierRegistry;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\Contracts\PasskeyService;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationExpectation;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\CredentialDescriptor;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Events\PasskeyAuthenticated;
use RoundlyConsulting\Passkeys\Events\PasskeyRegistered;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyAssertionFailed;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\CredentialOwner;
use RoundlyConsulting\Passkeys\Support\PasskeyModel;
use RoundlyConsulting\Passkeys\UserPasskeys;

/**
 * A first-class, no-crypto testing double for {@see PasskeyService}, swapped in by
 * Passkeys::fake(). It performs NO CBOR/COSE decode, NO signature verification,
 * and NO challenge check — ceremony outcomes are programmable and every
 * register() / authenticate() is recorded so a host can assert its passkey
 * enrolment and login flow without reproducing authenticator crypto.
 *
 * The side effects stay real: a successful register() stores the credential and
 * fires `PasskeyRegistered`; a successful authenticate() stamps `last_used_at` and
 * fires `PasskeyAuthenticated` — through the container's event dispatcher, so the
 * host's listeners run unless the test wraps them in `Event::fake()`. A programmed
 * failure writes and fires nothing. A revoked (or unsaved) passkey is refused, and so
 * is one whose owner no longer holds it — deleted, soft-deleted, or holding another
 * user handle — through the real verifier's own owner check. The one exemption is the
 * passkey the fake invents when nothing is seeded, which stands for "any valid
 * credential".
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
     * service, once it is revoked, when it was never saved, or when its owner no
     * longer holds it. Seed it with `Passkey::factory()->forAuthenticatable($user)`,
     * which gives it the user's handle.
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
     * Creation options for `for($user)->registrationOptions()`: the canned ceremony id,
     * challenge and relying party, everything else as the real action builds it — the
     * overrides, the configured defaults and the account's active passkeys in
     * excludeCredentials. The relying party and origins are never required, so a host
     * test with none configured still works.
     *
     * @internal called by the recording handle
     */
    public function fakeRegistrationOptions(HasPasskeys $user, ?RegistrationOptionsOverrides $overrides = null): CreationOptionsData
    {
        $config = $this->config();

        return new CreationOptionsData(
            ceremonyId: self::CANNED_CEREMONY_ID,
            rpId: 'localhost',
            rpName: 'Fake',
            userHandle: self::decode($user->passkeyUserHandle()),
            userName: $user->passkeyUserName(),
            userDisplayName: $user->passkeyDisplayName(),
            challenge: self::CANNED_CHALLENGE,
            algorithms: $config->algorithms,
            timeoutMs: $overrides->timeoutMs ?? $config->timeoutMs,
            attestation: $overrides->attestation ?? $config->attestation,
            userVerification: $overrides->userVerification ?? $config->userVerification,
            excludeCredentials: self::descriptors($user),
            residentKey: $overrides->residentKey ?? $config->residentKey,
            authenticatorAttachment: $overrides?->authenticatorAttachment,
        );
    }

    /**
     * The account's active passkeys as credential descriptors, as the real options
     * list them.
     *
     * @return list<CredentialDescriptor>
     *
     * @throws InvalidClientData
     */
    private static function descriptors(HasPasskeys $user): array
    {
        return array_values($user->passkeys()->get()
            ->map(static fn (Passkey $passkey): CredentialDescriptor => new CredentialDescriptor(
                id: self::decode($passkey->credential_id),
                transports: $passkey->transports,
            ))
            ->all());
    }

    /**
     * Stored values (the user handle, credential ids) are base64url; the options carry
     * them RAW and serialise them back themselves, so they are decoded exactly as the
     * real service decodes them — including refusing a malformed one.
     *
     * @throws InvalidClientData
     */
    private static function decode(string $value): string
    {
        try {
            return Base64Url::decode($value);
        } catch (InvalidEncodingException) {
            throw InvalidClientData::malformed();
        }
    }

    private function config(): PasskeyConfig
    {
        return $this->container->make(PasskeyConfig::class);
    }

    /**
     * Persist a factory credential for `for($user)->register()` and fire
     * `PasskeyRegistered`, recorded — or throw the programmed exception.
     *
     * @internal called by the recording handle
     */
    public function fakeRegister(Model&HasPasskeys $user, ?string $name = null): Passkey
    {
        if ($this->registrationError !== null) {
            throw $this->registrationError;
        }

        // Never used yet, like a real registration: only a sign-in stamps usage.
        $passkey = Passkey::factory()->es256()->make([
            'user_handle' => $user->passkeyUserHandle(),
            'name' => $name,
            'last_used_at' => null,
        ]);

        $user->passkeys()->save($passkey);

        $this->container->make(Dispatcher::class)->dispatch(new PasskeyRegistered($passkey));

        $this->registrations[] = ['user' => $user, 'passkey' => $passkey, 'name' => $name];

        return $passkey;
    }

    /**
     * Request options for the flat and the scoped ceremony: the canned ceremony id,
     * challenge and relying party, the overrides and configured defaults, and — for
     * `for($user)` — the account's active passkeys in allowCredentials. The flat,
     * usernameless request offers none, as the real one does.
     *
     * @internal called by the recording handle
     */
    public function fakeAuthenticationOptions(?AuthenticationOptionsOverrides $overrides = null, ?HasPasskeys $user = null): RequestOptionsData
    {
        $config = $this->config();

        return new RequestOptionsData(
            ceremonyId: self::CANNED_CEREMONY_ID,
            rpId: 'localhost',
            challenge: self::CANNED_CHALLENGE,
            timeoutMs: $overrides->timeoutMs ?? $config->timeoutMs,
            userVerification: $overrides->userVerification ?? $config->userVerification,
            allowCredentials: $user === null ? [] : self::descriptors($user),
        );
    }

    /**
     * The programmed authentication outcome, recorded; a success stamps usage and
     * fires `PasskeyAuthenticated`. The passkey must pass the real verifier's checks
     * that need no crypto: still stored and not revoked, held by its owner, and
     * meeting the expectation — in that order.
     *
     * @internal called by the recording handle
     */
    public function fakeAuthenticate(?AuthenticationExpectation $expect = null): Passkey
    {
        if (! $this->acceptsAuthentication) {
            throw $this->failedAuthentication();
        }

        $passkey = $this->authenticatesAs ?? $this->lastRegisteredPasskey();

        // Nothing seeded: the fake invents "any valid credential". That passkey is the
        // one exemption from the owner check — its factory owner is a placeholder, not
        // an account. Every passkey a test hands over or registers is checked.
        $invented = $passkey === null;
        $passkey ??= self::inventPasskey();

        if (! self::isActive($passkey)
            || (! $invented && ! self::ownerHolds($passkey))
            || ($expect !== null && ! $expect->matches($passkey))) {
            throw $this->failedAuthentication();
        }

        // Stamped like a real sign-in (`last_used_at`); the counter is not moved.
        $passkey->recordUsage($passkey->backup_state);

        $this->container->make(Dispatcher::class)->dispatch(new PasskeyAuthenticated($passkey));

        $this->authentications[] = ['passkey' => $passkey, 'success' => true];

        return $passkey;
    }

    private function failedAuthentication(): CredentialNotFound
    {
        $this->authentications[] = ['passkey' => null, 'success' => false];

        return CredentialNotFound::make();
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

    /**
     * The real verifier's owner check ({@see CredentialOwner::holds()}): the owner
     * still exists, is not soft-deleted, and still holds the passkey's user handle.
     * An owner type that names no model (the factory's default `user`) is refused as
     * a missing owner, never a class-not-found error.
     */
    private static function ownerHolds(Passkey $passkey): bool
    {
        return CredentialOwner::resolvable($passkey) && CredentialOwner::holds($passkey);
    }

    private function lastRegisteredPasskey(): ?Passkey
    {
        $last = end($this->registrations);

        return $last === false ? null : $last['passkey'];
    }

    private static function inventPasskey(): Passkey
    {
        /** @var Passkey $passkey */
        $passkey = Passkey::factory()->es256()->create();

        return $passkey;
    }
}
