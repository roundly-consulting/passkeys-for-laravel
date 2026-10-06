<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\UniqueConstraintViolationException;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Passkeys\Attestation\AttestationResult;
use RoundlyConsulting\Passkeys\Attestation\AttestationVerifier;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;
use RoundlyConsulting\Passkeys\DataTransferObjects\ClientData;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Enums\CeremonyType;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Events\PasskeyRegistered;
use RoundlyConsulting\Passkeys\Exceptions\ChallengeExpired;
use RoundlyConsulting\Passkeys\Exceptions\ChallengeMismatch;
use RoundlyConsulting\Passkeys\Exceptions\CredentialAlreadyRegistered;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAuthenticatorData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Exceptions\OriginMismatch;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Exceptions\RpIdMismatch;
use RoundlyConsulting\Passkeys\Exceptions\UnsupportedAlgorithm;
use RoundlyConsulting\Passkeys\Exceptions\UserVerificationRequired;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\Aaguid;
use RoundlyConsulting\Passkeys\Support\CredentialCrypto;
use RoundlyConsulting\Passkeys\Support\PasskeyModel;

/**
 * Verifies a registration (attestation) response and persists the credential,
 * following the WebAuthn spec §7.1 registration verification order exactly.
 *
 * The primitives (CBOR, COSE, base64url, SHA-256, constant-time compare) belong
 * to crypto-for-laravel; the ceremony — challenge binding, origin, rpIdHash,
 * flag policy, algorithm allow-list, attestation trust — stays here.
 */
final readonly class VerifyRegistrationAction
{
    private Digest $digest;

    public function __construct(
        private ChallengeRepository $challenges,
        private CredentialCrypto $crypto,
        private AttestationVerifier $attestation,
        private PasskeyConfig $config,
        private Dispatcher $events,
    ) {
        $this->digest = new Digest;
    }

    /**
     * @throws PasskeyException
     */
    public function execute(HasPasskeys $user, RegistrationResponseData $response, ?string $name = null): Passkey
    {
        $rpId = $this->config->requireRpId();
        $origins = $this->config->requireOrigins();

        // §7.1.6-8 — decode and type-check clientDataJSON.
        $clientData = ClientData::fromJson($response->clientDataJson);

        if ($clientData->type !== 'webauthn.create') {
            throw InvalidClientData::wrongType('webauthn.create');
        }

        // §7.1.9 — challenge equals the stored, single-use one (constant-time).
        $challenge = $this->pullChallenge($response->ceremonyId);

        // The stored challenge must have been minted for a registration ceremony.
        if ($challenge->type !== CeremonyType::Registration) {
            throw ChallengeMismatch::ceremonyType();
        }

        if (! ConstantTime::equals($challenge->challenge, $clientData->challenge)) {
            throw ChallengeMismatch::make();
        }

        // Bind the credential to the user the challenge was issued for, so an
        // admin-on-behalf flow cannot attach it to a different account.
        $this->assertUserHandle($user, $challenge);

        // §7.1.10-11 — origin allow-list + cross-origin policy.
        $this->assertOrigin($clientData, $origins);

        // §7.1.12 — hash of clientDataJSON.
        $clientDataHash = $this->digest->raw($response->clientDataJson);

        // §7.1.13 — CBOR-decode the attestation object (trailing-byte strict).
        $attestation = $this->crypto->attestationObject($response->attestationObject);

        // §7.1.14-16 — parse authenticator data, verify rpIdHash + flags.
        $parsed = $this->crypto->authenticatorData($attestation->authenticatorData);

        if (! ConstantTime::equals($this->digest->raw($rpId), $parsed->rpIdHash)) {
            throw RpIdMismatch::make();
        }

        $this->assertFlags($parsed, $challenge->userVerification);

        // §7.1.16 — attested credential data + a supported, offered algorithm.
        if ($parsed->coseKey === null || $parsed->credentialId === null || $parsed->coseKeyBytes === null) {
            throw InvalidAuthenticatorData::attestedDataMissing();
        }

        // The algorithm is read off the credential's own key and held against the
        // configured allow-list — the response never gets to name one.
        $algorithm = $this->crypto->coseAlgorithm($parsed->coseKey);

        if (! in_array($algorithm->value, $this->config->algorithms, true)) {
            throw UnsupportedAlgorithm::forId($algorithm->value);
        }

        // §7.1.19 — verify (or record) the attestation statement. The binding is
        // the trust gate: what it accepts is policy, configured, not decided here.
        $result = $this->attestation->verify($attestation, $parsed, $clientDataHash);

        // §7.1.22 — the credential id must not already be registered. The pre-check is
        // the fast path; the unique index decides a race between two ceremonies.
        $credentialId = Base64Url::encode($parsed->credentialId);

        if (PasskeyModel::query()->forCredentialId($credentialId)->withTrashed()->exists()) {
            throw CredentialAlreadyRegistered::make();
        }

        try {
            $passkey = $this->persist($user, $response, $parsed, $credentialId, $result, $name);
        } catch (UniqueConstraintViolationException) {
            throw CredentialAlreadyRegistered::make();
        }

        $this->events->dispatch(new PasskeyRegistered($passkey));

        return $passkey;
    }

    private function assertUserHandle(HasPasskeys $user, ChallengeData $challenge): void
    {
        // A null handle means the challenge recorded no binding; nothing to enforce.
        if ($challenge->userHandle === null) {
            return;
        }

        if (! ConstantTime::equals($challenge->userHandle, $user->passkeyUserHandle())) {
            throw ChallengeMismatch::userHandle();
        }
    }

    private function pullChallenge(?string $ceremonyId): ChallengeData
    {
        if ($ceremonyId === null) {
            throw ChallengeExpired::make();
        }

        return $this->challenges->pull($ceremonyId) ?? throw ChallengeExpired::make();
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

        // A credential cannot be "backed up" without being "backup eligible".
        if ($parsed->flags->backupState && ! $parsed->flags->backupEligible) {
            throw InvalidAuthenticatorData::backupStateInconsistent();
        }
    }

    private function persist(
        HasPasskeys $user,
        RegistrationResponseData $response,
        AuthenticatorData $parsed,
        string $credentialId,
        AttestationResult $result,
        ?string $name,
    ): Passkey {
        /** @var Passkey $passkey */
        $passkey = $user->passkeys()->create([
            'credential_id' => $credentialId,
            'credential_id_hash' => Passkey::hashCredentialId($credentialId),
            'public_key' => $this->crypto->encodePublicKey((string) $parsed->coseKeyBytes),
            'user_handle' => $user->passkeyUserHandle(),
            'transports' => $response->transports,
            'aaguid' => Aaguid::format($parsed->aaguid),
            'sign_count' => $parsed->signCount,
            'name' => $name,
            'attestation_format' => $result->format,
            'attestation_type' => $result->type->value,
            'backup_eligible' => $parsed->flags->backupEligible,
            'backup_state' => $parsed->flags->backupState,
        ]);

        return $passkey;
    }
}
