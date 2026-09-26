<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use RoundlyConsulting\Passkeys\Enums\CeremonyType;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * The server-side context stored for an in-flight ceremony, keyed by a random
 * ceremony id. Held single-use in the challenge store until the response lands.
 * The ceremony `type` binds the challenge to the ceremony that minted it, so a
 * registration challenge can never be redeemed at the authentication verifier
 * (or vice versa).
 *
 * An authentication ceremony minted for a known user also carries that user's
 * handle and the sha-256 digests of the credential ids it offered in
 * allowCredentials, so the verifier can refuse any other account's credential
 * (WebAuthn L3 §7.2 steps 5–6). A discoverable ceremony carries neither.
 */
final readonly class ChallengeData
{
    /**
     * @param  list<int>  $algorithms
     * @param  list<string>  $allowedCredentialHashes  {@see Passkey::hashCredentialId()} digests
     */
    public function __construct(
        public string $challenge,
        public UserVerification $userVerification,
        public array $algorithms,
        public CeremonyType $type = CeremonyType::Registration,
        public ?string $userHandle = null,
        public array $allowedCredentialHashes = [],
    ) {}

    /**
     * @return array{challenge: string, user_verification: string, algorithms: list<int>, type: string, user_handle: string|null, allowed_credential_hashes: list<string>}
     */
    public function toArray(): array
    {
        return [
            'challenge' => $this->challenge,
            'user_verification' => $this->userVerification->value,
            'algorithms' => $this->algorithms,
            'type' => $this->type->value,
            'user_handle' => $this->userHandle,
            'allowed_credential_hashes' => $this->allowedCredentialHashes,
        ];
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        /** @var list<int> $algorithms */
        $algorithms = array_values(array_filter(
            is_array($data['algorithms'] ?? null) ? $data['algorithms'] : [],
            'is_int',
        ));

        // Tolerates a payload written before the allow-list existed: a challenge
        // stored by the previous release simply carries no restriction.
        /** @var list<string> $allowedCredentialHashes */
        $allowedCredentialHashes = array_values(array_filter(
            is_array($data['allowed_credential_hashes'] ?? null) ? $data['allowed_credential_hashes'] : [],
            'is_string',
        ));

        $userHandle = $data['user_handle'] ?? null;
        $type = is_string($data['type'] ?? null) ? CeremonyType::tryFrom($data['type']) : null;

        return new self(
            challenge: is_string($data['challenge'] ?? null) ? $data['challenge'] : '',
            userVerification: UserVerification::from(is_string($data['user_verification'] ?? null) ? $data['user_verification'] : 'preferred'),
            algorithms: $algorithms,
            type: $type ?? CeremonyType::Registration,
            userHandle: is_string($userHandle) ? $userHandle : null,
            allowedCredentialHashes: $allowedCredentialHashes,
        );
    }
}
