<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\AttestationTrust;
use RoundlyConsulting\Passkeys\Enums\CoseAlgorithm;
use RoundlyConsulting\Passkeys\Enums\ResidentKey;
use RoundlyConsulting\Passkeys\Enums\SignCountPolicy;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Exceptions\InvalidConfiguration;

/**
 * A typed, validated view over `config/passkeys.php`. Security-critical values
 * (rp.id, origins) are resolved eagerly but only *enforced* when a ceremony
 * actually needs them, so the package boots with zero host configuration.
 */
final readonly class PasskeyConfig
{
    /**
     * @param  list<string>  $origins
     * @param  list<int>  $algorithms
     */
    public function __construct(
        public ?string $rpId,
        public string $rpName,
        public array $origins,
        public bool $allowCrossOrigin,
        public array $algorithms,
        public int $timeoutMs,
        public AttestationConveyance $attestation,
        public UserVerification $userVerification,
        public ResidentKey $residentKey,
        public ?string $challengeStore,
        public int $challengeTtl,
        public int $challengeBytes,
        public SignCountPolicy $signCountPolicy,
        public AttestationTrust $attestationTrust,
        public bool $rejectUnknownFmt,
        public string $userHandleColumn,
        public int $userHandleBytes,
        public string $userNameAttribute,
        public string $userDisplayNameAttribute,
    ) {}

    /**
     * @param  array<string, mixed>  $config
     */
    public static function fromArray(array $config, ?string $appUrl = null): self
    {
        $rp = is_array($config['rp'] ?? null) ? $config['rp'] : [];
        $challenge = is_array($config['challenge'] ?? null) ? $config['challenge'] : [];
        $user = is_array($config['user'] ?? null) ? $config['user'] : [];

        $rpId = is_string($rp['id'] ?? null) && $rp['id'] !== '' ? $rp['id'] : self::hostFromUrl($appUrl);

        /** @var list<string> $origins */
        $origins = array_values(array_filter(
            is_array($config['origins'] ?? null) ? $config['origins'] : [],
            static fn (mixed $origin): bool => is_string($origin) && $origin !== '',
        ));

        /** @var list<int> $algorithms */
        $algorithms = array_values(array_filter(
            is_array($config['algorithms'] ?? null) ? $config['algorithms'] : [],
            'is_int',
        ));

        if ($algorithms === []) {
            $algorithms = [CoseAlgorithm::ES256->value, CoseAlgorithm::RS256->value];
        }

        $attestationTrust = AttestationTrust::from(is_string($config['attestation_trust'] ?? null) ? $config['attestation_trust'] : 'ignore');

        // Only `ignore` is honoured today — self/basic attestation is not yet
        // verified, so accepting them would grant a false sense of trust. Fail
        // loudly at config-parse time rather than silently skipping verification.
        if ($attestationTrust !== AttestationTrust::Ignore) {
            throw InvalidConfiguration::unsupportedAttestationTrust($attestationTrust->value);
        }

        return new self(
            rpId: $rpId,
            rpName: is_string($rp['name'] ?? null) ? $rp['name'] : 'Laravel',
            origins: $origins,
            allowCrossOrigin: (bool) ($config['allow_cross_origin'] ?? false),
            algorithms: $algorithms,
            timeoutMs: (int) ($config['timeout_ms'] ?? 60_000),
            attestation: AttestationConveyance::from(is_string($config['attestation'] ?? null) ? $config['attestation'] : 'none'),
            userVerification: UserVerification::from(is_string($config['user_verification'] ?? null) ? $config['user_verification'] : 'required'),
            residentKey: ResidentKey::from(is_string($config['resident_key'] ?? null) ? $config['resident_key'] : 'required'),
            challengeStore: is_string($challenge['store'] ?? null) && $challenge['store'] !== '' ? $challenge['store'] : null,
            challengeTtl: (int) ($challenge['ttl'] ?? 60),
            challengeBytes: (int) ($challenge['bytes'] ?? 32),
            signCountPolicy: SignCountPolicy::from(is_string($config['sign_count_policy'] ?? null) ? $config['sign_count_policy'] : 'flag'),
            attestationTrust: $attestationTrust,
            rejectUnknownFmt: (bool) ($config['reject_unknown_fmt'] ?? false),
            userHandleColumn: is_string($user['handle_column'] ?? null) ? $user['handle_column'] : 'passkey_user_handle',
            userHandleBytes: (int) ($user['handle_bytes'] ?? 32),
            userNameAttribute: is_string($user['name_attribute'] ?? null) ? $user['name_attribute'] : 'email',
            userDisplayNameAttribute: is_string($user['display_name_attribute'] ?? null) ? $user['display_name_attribute'] : 'name',
        );
    }

    /**
     * @throws InvalidConfiguration
     */
    public function requireRpId(): string
    {
        if ($this->rpId === null || $this->rpId === '') {
            throw InvalidConfiguration::missingRpId();
        }

        return $this->rpId;
    }

    /**
     * @return list<string>
     *
     * @throws InvalidConfiguration
     */
    public function requireOrigins(): array
    {
        if ($this->origins === []) {
            throw InvalidConfiguration::emptyOrigins();
        }

        return $this->origins;
    }

    private static function hostFromUrl(?string $url): ?string
    {
        if ($url === null || $url === '') {
            return null;
        }

        $host = parse_url($url, PHP_URL_HOST);

        return is_string($host) && $host !== '' ? $host : null;
    }
}
