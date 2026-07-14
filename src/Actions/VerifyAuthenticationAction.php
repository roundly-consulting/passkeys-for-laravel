<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
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
final class VerifyAuthenticationAction
{
    private readonly Digest $digest;

    public function __construct(
        private readonly ChallengeRepository $challenges,
        private readonly CredentialCrypto $crypto,
        private readonly PasskeyConfig $config,
        private readonly Dispatcher $events,
    ) {
        $this->digest = new Digest;
    }

    /**
     * @throws PasskeyException
     */
    public function execute(AuthenticationResponseData $response): Passkey
    {
        $rpId = $this->config->requireRpId();
        $origins = $this->config->requireOrigins();

        // §7.2.1-6 — locate the credential (uniform miss, no user enumeration).
        $passkey = $this->locateCredential($response);

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

        $this->assertOrigin($clientData, $origins);

        // §7.2.14-17 — verify rpIdHash + flags.
        $parsed = $this->crypto->authenticatorData($response->authenticatorData);

        if (! ConstantTime::equals($this->digest->raw($rpId), $parsed->rpIdHash)) {
            throw RpIdMismatch::make();
        }

        $this->assertFlags($parsed, $challenge->userVerification);

        // §7.2.20-21 — verify the signature over authData ‖ hash(clientDataJSON).
        $this->verifySignature($passkey, $response);

        // §7.2.22 — sign-counter regression handling.
        $this->reconcileSignCount($passkey, $parsed->signCount);

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

    private function assertFlags(AuthenticatorData $parsed, UserVerification $userVerification): void
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

    private function reconcileSignCount(Passkey $passkey, int $received): void
    {
        $stored = $passkey->sign_count;

        // Authenticators reporting a static 0 counter skip the comparison.
        if ($stored === 0 && $received === 0) {
            $passkey->touchUsage($received);

            return;
        }

        if ($received > $stored) {
            $passkey->touchUsage($received);

            return;
        }

        if ($this->config->signCountPolicy === SignCountPolicy::Reject) {
            throw SignCountRegression::make($stored, $received);
        }

        $this->events->dispatch(new PasskeySignCountRegressed($passkey, $stored, $received));
        $passkey->touchUsage($received);
    }
}
