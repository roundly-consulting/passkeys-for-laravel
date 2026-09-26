<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use RoundlyConsulting\Crypto\Cose\CoseAlgorithm;
use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\AttestationTrust;
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
     * The COSE algorithms this relying party will register and verify.
     *
     * crypto-for-laravel's COSE registry is deliberately wider than this (it also
     * carries ES384 and ES512). A relying party accepts only what it has vetted,
     * so the configured list is narrowed back to exactly these three — the set
     * WebAuthn authenticators actually mint — and anything else is rejected at
     * config-parse time rather than silently accepted through the shared enum.
     *
     * @var list<CoseAlgorithm>
     */
    public const array SUPPORTED_ALGORITHMS = [
        CoseAlgorithm::ES256,
        CoseAlgorithm::RS256,
        CoseAlgorithm::EdDSA,
    ];

    /**
     * The widest clock-skew leeway a host may grant an attestation certificate's
     * validity window. An hour is already generous for a wall clock; more is a
     * typo, not a policy.
     */
    public const int MAX_ATTESTATION_CLOCK_SKEW = 3600;

    /**
     * @param  list<string>  $origins
     * @param  list<int>  $algorithms
     * @param  array<string, list<string>>  $attestationAnchorPaths  format => absolute PEM paths
     * @param  list<string>  $allowedAaguids
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
        public bool $attestationAnchorDefaults,
        public array $attestationAnchorPaths,
        public int $attestationClockSkew,
        public array $allowedAaguids,
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

        self::assertSupportedAlgorithms($algorithms);

        $attestationTrust = AttestationTrust::from(is_string($config['attestation_trust'] ?? null) ? $config['attestation_trust'] : 'ignore');
        $attestation = AttestationConveyance::from(is_string($config['attestation'] ?? null) ? $config['attestation'] : 'none');

        // Demanding proof while telling authenticators not to attest would refuse
        // every registration, at ceremony time, for a reason the host cannot see.
        // One `if` at config-parse time instead.
        if ($attestationTrust !== AttestationTrust::Ignore && $attestation === AttestationConveyance::None) {
            throw InvalidConfiguration::attestationConveyanceMismatch($attestationTrust->value);
        }

        $anchors = is_array($config['attestation_anchors'] ?? null) ? $config['attestation_anchors'] : [];
        $aaguids = is_array($config['aaguids'] ?? null) ? $config['aaguids'] : [];

        return new self(
            rpId: $rpId,
            rpName: is_string($rp['name'] ?? null) ? $rp['name'] : 'Laravel',
            origins: $origins,
            allowCrossOrigin: (bool) ($config['allow_cross_origin'] ?? false),
            algorithms: $algorithms,
            timeoutMs: (int) ($config['timeout_ms'] ?? 60_000),
            attestation: $attestation,
            userVerification: UserVerification::from(is_string($config['user_verification'] ?? null) ? $config['user_verification'] : 'required'),
            residentKey: ResidentKey::from(is_string($config['resident_key'] ?? null) ? $config['resident_key'] : 'required'),
            challengeStore: is_string($challenge['store'] ?? null) && $challenge['store'] !== '' ? $challenge['store'] : null,
            challengeTtl: (int) ($challenge['ttl'] ?? 60),
            challengeBytes: (int) ($challenge['bytes'] ?? 32),
            signCountPolicy: SignCountPolicy::from(is_string($config['sign_count_policy'] ?? null) ? $config['sign_count_policy'] : 'flag'),
            attestationTrust: $attestationTrust,
            rejectUnknownFmt: (bool) ($config['reject_unknown_fmt'] ?? false),
            attestationAnchorDefaults: (bool) ($anchors['defaults'] ?? true),
            attestationAnchorPaths: self::anchorPaths($anchors['paths'] ?? null),
            attestationClockSkew: self::clockSkew($config['attestation_clock_skew'] ?? 60),
            allowedAaguids: self::aaguids($aaguids['allowed'] ?? null),
            userHandleColumn: is_string($user['handle_column'] ?? null) ? $user['handle_column'] : 'passkey_user_handle',
            userHandleBytes: (int) ($user['handle_bytes'] ?? 32),
            userNameAttribute: is_string($user['name_attribute'] ?? null) ? $user['name_attribute'] : 'email',
            userDisplayNameAttribute: is_string($user['display_name_attribute'] ?? null) ? $user['display_name_attribute'] : 'name',
        );
    }

    /**
     * How long to keep a ceremony's challenge: `challenge.ttl`, but never less than the
     * timeout the options hand the browser (rounded up to whole seconds). A ceremony the
     * user finishes inside the promised window must not be refused as expired, whether
     * the longer timeout comes from config or from a per-call override.
     */
    public function challengeTtlFor(int $timeoutMs): int
    {
        return max($this->challengeTtl, (int) ceil($timeoutMs / 1000));
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

    /**
     * The anchors configured for one format, or an empty list.
     *
     * @return list<string>
     */
    public function anchorPathsFor(string $format): array
    {
        return $this->attestationAnchorPaths[$format] ?? [];
    }

    /**
     * Host-supplied trust anchors, normalised to `format => list<path>`. A
     * non-string path or a non-list value is dropped rather than half-read.
     *
     * @return array<string, list<string>>
     */
    private static function anchorPaths(mixed $paths): array
    {
        if (! is_array($paths)) {
            return [];
        }

        $normalised = [];

        foreach ($paths as $format => $configured) {
            if (! is_string($format) || ! is_array($configured)) {
                continue;
            }

            /** @var list<string> $files */
            $files = array_values(array_filter(
                $configured,
                static fn (mixed $path): bool => is_string($path) && $path !== '',
            ));

            if ($files !== []) {
                $normalised[$format] = $files;
            }
        }

        return $normalised;
    }

    /**
     * @throws InvalidConfiguration
     */
    private static function clockSkew(mixed $value): int
    {
        if (! is_numeric($value)) {
            throw InvalidConfiguration::invalidClockSkew(
                is_scalar($value) ? (string) $value : gettype($value),
                self::MAX_ATTESTATION_CLOCK_SKEW,
            );
        }

        $seconds = (int) $value;

        if ($seconds < 0 || $seconds > self::MAX_ATTESTATION_CLOCK_SKEW) {
            throw InvalidConfiguration::invalidClockSkew((string) $seconds, self::MAX_ATTESTATION_CLOCK_SKEW);
        }

        return $seconds;
    }

    /**
     * @return list<string>
     */
    private static function aaguids(mixed $allowed): array
    {
        if (! is_array($allowed)) {
            return [];
        }

        /** @var list<string> $aaguids */
        $aaguids = array_values(array_map(
            'strtolower',
            array_filter(
                $allowed,
                static fn (mixed $aaguid): bool => is_string($aaguid) && $aaguid !== '',
            ),
        ));

        return $aaguids;
    }

    /**
     * Reject any configured COSE identifier outside {@see SUPPORTED_ALGORITHMS} —
     * including one crypto knows but this relying party does not — rather than
     * offering an algorithm the ceremony has never been vetted against.
     *
     * @param  list<int>  $algorithms
     *
     * @throws InvalidConfiguration
     */
    private static function assertSupportedAlgorithms(array $algorithms): void
    {
        $supported = array_map(
            static fn (CoseAlgorithm $algorithm): int => $algorithm->value,
            self::SUPPORTED_ALGORITHMS,
        );

        foreach ($algorithms as $algorithm) {
            if (! in_array($algorithm, $supported, true)) {
                throw InvalidConfiguration::unsupportedAlgorithm($algorithm);
            }
        }
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
