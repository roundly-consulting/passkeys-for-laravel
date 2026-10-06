<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Passkeys\Concerns\InteractsWithPasskeys;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationExpectation;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;
use RoundlyConsulting\Passkeys\DataTransferObjects\ClientData;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\Enums\CeremonyType;
use RoundlyConsulting\Passkeys\Enums\SignCountPolicy;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Events\PasskeyAuthenticated;
use RoundlyConsulting\Passkeys\Events\PasskeySignCountRegressed;
use RoundlyConsulting\Passkeys\Exceptions\ChallengeExpired;
use RoundlyConsulting\Passkeys\Exceptions\ChallengeMismatch;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAuthenticatorData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Exceptions\OriginMismatch;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Exceptions\RpIdMismatch;
use RoundlyConsulting\Passkeys\Exceptions\SignatureInvalid;
use RoundlyConsulting\Passkeys\Exceptions\SignCountRegression;
use RoundlyConsulting\Passkeys\Exceptions\UserVerificationRequired;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\CredentialCrypto;
use RoundlyConsulting\Passkeys\Support\PasskeyModel;
use RoundlyConsulting\Passkeys\Support\UserHandleColumn;

/**
 * Verifies an authentication (assertion) response and advances the sign counter,
 * following the WebAuthn spec §7.2 authentication verification order exactly.
 * Every credential-location miss surfaces a uniform CredentialNotFound so
 * registered users cannot be enumerated.
 *
 * The signature is checked against the key of the *stored* credential, so the
 * algorithm is always the one that credential was registered with — the assertion
 * never gets to choose it.
 */
final readonly class VerifyAuthenticationAction
{
    private Digest $digest;

    public function __construct(
        private ChallengeRepository $challenges,
        private CredentialCrypto $crypto,
        private PasskeyConfig $config,
        private Dispatcher $events,
    ) {
        $this->digest = new Digest;
    }

    /**
     * @throws PasskeyException
     */
    public function execute(AuthenticationResponseData $response, ?AuthenticationExpectation $expect = null): Passkey
    {
        $rpId = $this->config->requireRpId();
        $origins = $this->config->requireOrigins();

        // §7.2.1-6 — locate the credential (uniform miss, no user enumeration) and
        // the account that still holds it.
        $passkey = $this->locateCredential($response);
        $this->assertOwnerHoldsCredential($passkey);

        // The caller's owner expectation is checked before the challenge is pulled,
        // so a credential of the wrong owner neither burns the ceremony nor gets its
        // counter touched — the right owner can still finish.
        if ($expect !== null && ! $expect->matches($passkey)) {
            throw CredentialNotFound::make();
        }

        // §7.2.11-13 — decode + type-check + challenge + origin.
        $clientData = ClientData::fromJson($response->clientDataJson);

        if ($clientData->type !== 'webauthn.get') {
            throw InvalidClientData::wrongType('webauthn.get');
        }

        $challenge = $this->challenges->pull((string) $response->ceremonyId) ?? throw ChallengeExpired::make();

        // The stored challenge must have been minted for an authentication ceremony.
        if ($challenge->type !== CeremonyType::Authentication) {
            throw ChallengeMismatch::ceremonyType();
        }

        if (! ConstantTime::equals($challenge->challenge, $clientData->challenge)) {
            throw ChallengeMismatch::make();
        }

        // §7.2.5-6 — a ceremony minted for a known user only accepts that user's
        // credentials, and only those it offered in allowCredentials; a
        // usernameless one needs the response itself to name the account.
        $this->assertBoundToCeremony($passkey, $challenge, $response);

        $this->assertOrigin($clientData, $origins);

        // §7.2.14-17 — verify rpIdHash + flags.
        $parsed = $this->crypto->authenticatorData($response->authenticatorData);

        if (! ConstantTime::equals($this->digest->raw($rpId), $parsed->rpIdHash)) {
            throw RpIdMismatch::make();
        }

        $this->assertFlags($parsed, $challenge->userVerification, $passkey);

        // §7.2.20-21 — verify the signature over authData ‖ hash(clientDataJSON).
        $this->verifySignature($passkey, $response);

        // §7.2.21-26 — sign-counter regression handling, backup state update.
        $this->reconcileSignCount($passkey, $parsed);

        $this->events->dispatch(new PasskeyAuthenticated($passkey));

        return $passkey;
    }

    private function locateCredential(AuthenticationResponseData $response): Passkey
    {
        $credentialId = Base64Url::encode($response->rawId);

        $passkey = PasskeyModel::query()->forCredentialId($credentialId)->first();

        if ($passkey === null) {
            throw CredentialNotFound::make();
        }

        // A discoverable login carries the user handle; it must match the stored one.
        if ($response->userHandle !== null
            && ! ConstantTime::equals($passkey->user_handle, Base64Url::encode($response->userHandle))) {
            throw CredentialNotFound::make();
        }

        return $passkey;
    }

    /**
     * The owner must still exist — a soft-deleted one is gone, as Laravel's own user
     * provider sees it — and must still hold the handle the credential was minted
     * for, so an account that reuses a deleted owner's id never inherits its
     * passkeys. Checked before the challenge is pulled, with the uniform miss.
     *
     * The shipped concern's handle is read straight off its column: asking the
     * concern would mint a handle for an account that has none, and a fresh random
     * handle can never match anyway. Any other implementation is asked through the
     * contract.
     */
    private function assertOwnerHoldsCredential(Passkey $passkey): void
    {
        // Not `$passkey->authenticatable`: loading the relation would add the owner
        // to the returned passkey's array/JSON form.
        $owner = $passkey->authenticatable()->getResults();

        if ($owner === null) {
            throw CredentialNotFound::make();
        }

        if ($owner instanceof HasPasskeys && ! ConstantTime::equals(self::storedHandle($owner), $passkey->user_handle)) {
            throw CredentialNotFound::make();
        }
    }

    private static function storedHandle(Model&HasPasskeys $owner): string
    {
        if (! in_array(InteractsWithPasskeys::class, class_uses_recursive($owner), true)) {
            return $owner->passkeyUserHandle();
        }

        $handle = $owner->getAttribute(UserHandleColumn::name());

        return is_string($handle) ? $handle : '';
    }

    /**
     * The browser omits `userHandle` for a non-discoverable credential, so the
     * response alone cannot prove whose passkey signed. The challenge can: it
     * remembers who the options were minted for. When it remembers nobody (a
     * usernameless ceremony), §7.2 step 6 requires the response to carry the
     * handle — {@see locateCredential()} already held it to the credential.
     * Misses stay the uniform not-found error, so the check leaks nothing about
     * other accounts.
     */
    private function assertBoundToCeremony(Passkey $passkey, ChallengeData $challenge, AuthenticationResponseData $response): void
    {
        if ($challenge->userHandle === null && $response->userHandle === null) {
            throw CredentialNotFound::make();
        }

        if ($challenge->userHandle !== null && ! ConstantTime::equals($challenge->userHandle, $passkey->user_handle)) {
            throw CredentialNotFound::make();
        }

        if ($challenge->allowedCredentialHashes !== []
            && ! in_array($passkey->credential_id_hash, $challenge->allowedCredentialHashes, true)) {
            throw CredentialNotFound::make();
        }
    }

    /**
     * @param  list<string>  $origins
     */
    private function assertOrigin(ClientData $clientData, array $origins): void
    {
        if (! in_array($clientData->origin, $origins, true)) {
            throw OriginMismatch::make();
        }

        if ($clientData->crossOrigin && ! $this->config->allowCrossOrigin) {
            throw OriginMismatch::crossOrigin();
        }
    }

    private function assertFlags(AuthenticatorData $parsed, UserVerification $userVerification, Passkey $passkey): void
    {
        if (! $parsed->flags->userPresent) {
            throw InvalidAuthenticatorData::userPresenceMissing();
        }

        if ($userVerification === UserVerification::Required && ! $parsed->flags->userVerified) {
            throw UserVerificationRequired::make();
        }

        if ($parsed->flags->backupState && ! $parsed->flags->backupEligible) {
            throw InvalidAuthenticatorData::backupStateInconsistent();
        }

        // L3 §7.2.19 — backup ELIGIBILITY is fixed at creation; only the backup
        // STATE may change between assertions.
        if ($parsed->flags->backupEligible !== $passkey->backup_eligible) {
            throw InvalidAuthenticatorData::backupEligibilityChanged();
        }
    }

    private function verifySignature(Passkey $passkey, AuthenticationResponseData $response): void
    {
        // The key — and therefore the algorithm — comes from the stored credential,
        // never from the assertion, which is what makes algorithm confusion
        // impossible here.
        $key = $this->crypto->storedPublicKey($passkey);

        $signedData = $response->authenticatorData.$this->digest->raw($response->clientDataJson);

        if (! $this->crypto->verify($key, $signedData, $response->signature)) {
            throw SignatureInvalid::make();
        }
    }

    /**
     * §7.2.21 — the counter only ever moves forward, and the database decides:
     * one conditional UPDATE, so neither a regression nor a concurrent assertion
     * that advanced it first can ever write a lower counter back. Under `flag` a
     * clone therefore keeps being flagged on every assertion it makes. The
     * backup state (BS) is current state, recorded on every accepted assertion.
     */
    private function reconcileSignCount(Passkey $passkey, AuthenticatorData $parsed): void
    {
        $received = $parsed->signCount;
        $backupState = $parsed->flags->backupState;

        if ($passkey->advanceSignCount($received, $backupState)) {
            return;
        }

        // Revoked while this assertion was being verified.
        if ($passkey->trashed()) {
            throw CredentialNotFound::make();
        }

        // Reloaded: what is stored NOW, at or beyond what was received.
        $stored = $passkey->sign_count;

        if ($this->config->signCountPolicy === SignCountPolicy::Reject) {
            throw SignCountRegression::make($stored, $received);
        }

        $this->events->dispatch(new PasskeySignCountRegressed($passkey, $stored, $received));
        $passkey->recordUsage($backupState);
    }
}
