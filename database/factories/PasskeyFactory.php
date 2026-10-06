<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Random\Bytes;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\PasskeyModel;

/**
 * @extends Factory<Passkey>
 */
final class PasskeyFactory extends Factory
{
    protected $model = Passkey::class;

    /**
     * Build the CONFIGURED model, not the packaged one: a host that swaps
     * `passkeys.model` gets its own class out of the factory too, so the fake and
     * the seeded fixtures match what a real ceremony persists.
     *
     * @return class-string<Passkey>
     */
    public function modelName(): string
    {
        return PasskeyModel::class();
    }

    /**
     * A valid ES256 (P-256) COSE key, base64-encoded, so a factory-built passkey
     * carries a decodable public key without pulling in any CBOR/COSE library.
     */
    private const ES256_COSE_KEY = 'pQECAyYgASFYIIQMDyY3s9K6LZYHzqSMVK7PQluvNG5h6hYFuN42SrulIlggvLM+FoEu5f7dYBCl7UhdPgBpjhqlxXHpMmDdgwN7bPA=';

    /**
     * A valid RS256 (RSA-2048) COSE key, base64-encoded.
     */
    private const RS256_COSE_KEY = 'pAEDAzkBACBZAQCTcTiHTnHVnNUVCXOhtDSv3JONslJXb8czvlgOYWWdQOn3pfo+qqTpKJT++sWya0VDIf8rVJwwdasamiVW5wdu9tH7WkCajw2OU7/MPzavYLWbn48ynUX9v2tT/sO7JwGPOe9KNX+xDVPwHs+gfOhBPE1/LdHQ0p20QE1BN5Nptwn+UQjXIKRK2iT9R/volrkj7OH3QzRHMvpEKzJbyRR1y+NvTRQ6E5SBKRbwX2E/alCPBe+B0/FxaPivBRcSOcKxDPdXBzz42HrZHvE1AaYKu3E2anMAIU8iWO2r05o19YLe19KJokxOh+RftYRrHHjHg8miCDNJf0DvNEp0afVZIUMBAAE=';

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $credentialId = Base64Url::encode(Bytes::generate(32));

        return [
            'authenticatable_type' => 'user',
            'authenticatable_id' => $this->faker->randomNumber(),
            'credential_id' => $credentialId,
            'credential_id_hash' => Passkey::hashCredentialId($credentialId),
            'public_key' => self::ES256_COSE_KEY,
            'user_handle' => Base64Url::encode(Bytes::generate(32)),
            'transports' => ['internal', 'hybrid'],
            'aaguid' => $this->faker->uuid(),
            'sign_count' => $this->faker->numberBetween(0, 50),
            'name' => null,
            'attestation_format' => 'none',
            'attestation_type' => null,
            'backup_eligible' => true,
            'backup_state' => true,
            'last_used_at' => now(),
        ];
    }

    public function es256(): self
    {
        return $this->state(fn (): array => [
            'public_key' => self::ES256_COSE_KEY,
            'attestation_format' => 'none',
        ]);
    }

    public function rs256(): self
    {
        return $this->state(fn (): array => [
            'public_key' => self::RS256_COSE_KEY,
            'attestation_format' => 'none',
        ]);
    }

    /**
     * State that keys the credential on an explicit id (and its lookup hash).
     */
    public function withCredentialId(string $credentialId): self
    {
        return $this->state(fn (): array => [
            'credential_id' => $credentialId,
            'credential_id_hash' => Passkey::hashCredentialId($credentialId),
        ]);
    }

    /**
     * State that hands the credential to `$model`. A `HasPasskeys` owner also gives it
     * its user handle — minted on the model if it has none yet, as a real registration
     * does — so the passkey is one its owner holds. Any other model keeps the random
     * handle and is left untouched.
     */
    public function forAuthenticatable(Model $model): self
    {
        return $this->state(fn (): array => [
            'authenticatable_type' => $model->getMorphClass(),
            'authenticatable_id' => $model->getKey(),
            ...($model instanceof HasPasskeys ? ['user_handle' => $model->passkeyUserHandle()] : []),
        ]);
    }

    public function neverUsed(): self
    {
        return $this->state(fn (): array => [
            'sign_count' => 0,
            'last_used_at' => null,
        ]);
    }
}
