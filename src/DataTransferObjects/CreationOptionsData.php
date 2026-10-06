<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use JsonSerializable;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\AuthenticatorAttachment;
use RoundlyConsulting\Passkeys\Enums\ResidentKey;
use RoundlyConsulting\Passkeys\Enums\UserVerification;

/**
 * PublicKeyCredentialCreationOptions, serialised to the WebAuthn JSON form
 * (`PublicKeyCredentialCreationOptionsJSON`, binary members base64url-encoded)
 * under `publicKey`. The browser takes it through
 * `PublicKeyCredential.parseCreationOptionsFromJSON()` before
 * `navigator.credentials.create()`. The ceremony id travels alongside so a
 * stateless host can echo it back with the registration response.
 */
final readonly class CreationOptionsData implements JsonSerializable
{
    /**
     * @param  list<int>  $algorithms
     * @param  list<CredentialDescriptor>  $excludeCredentials
     */
    public function __construct(
        public string $ceremonyId,
        public string $rpId,
        public string $rpName,
        public string $userHandle,
        public string $userName,
        public string $userDisplayName,
        public string $challenge,
        public array $algorithms,
        public int $timeoutMs,
        public AttestationConveyance $attestation,
        public UserVerification $userVerification,
        public array $excludeCredentials = [],
        public ResidentKey $residentKey = ResidentKey::Required,
        public ?AuthenticatorAttachment $authenticatorAttachment = null,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'ceremonyId' => $this->ceremonyId,
            'publicKey' => [
                'rp' => ['id' => $this->rpId, 'name' => $this->rpName],
                'user' => [
                    'id' => Base64Url::encode($this->userHandle),
                    'name' => $this->userName,
                    'displayName' => $this->userDisplayName,
                ],
                'challenge' => $this->challenge,
                'pubKeyCredParams' => array_map(
                    static fn (int $alg): array => ['type' => 'public-key', 'alg' => $alg],
                    $this->algorithms,
                ),
                'timeout' => $this->timeoutMs,
                'attestation' => $this->attestation->value,
                'excludeCredentials' => array_map(
                    static fn (CredentialDescriptor $descriptor): array => $descriptor->toArray(),
                    $this->excludeCredentials,
                ),
                'authenticatorSelection' => $this->authenticatorSelection(),
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function authenticatorSelection(): array
    {
        $selection = [
            'residentKey' => $this->residentKey->value,
            'requireResidentKey' => $this->residentKey->requireResidentKey(),
            'userVerification' => $this->userVerification->value,
        ];

        if ($this->authenticatorAttachment !== null) {
            $selection['authenticatorAttachment'] = $this->authenticatorAttachment->value;
        }

        return $selection;
    }
}
