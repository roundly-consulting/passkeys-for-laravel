<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\Base64Url;

/**
 * @extends Factory<Passkey>
 */
final class PasskeyFactory extends Factory
{
    protected $model = Passkey::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'authenticatable_type' => 'user',
            'authenticatable_id' => $this->faker->randomNumber(),
            'credential_id' => Base64Url::encode(random_bytes(32)),
            'public_key' => base64_encode(random_bytes(77)),
            'user_handle' => Base64Url::encode(random_bytes(32)),
            'transports' => ['internal', 'hybrid'],
            'aaguid' => $this->faker->uuid(),
            'sign_count' => $this->faker->numberBetween(0, 50),
            'name' => null,
            'attestation_format' => 'none',
            'backup_eligible' => true,
            'backup_state' => true,
            'last_used_at' => now(),
        ];
    }

    public function es256(): self
    {
        return $this->state(fn (): array => ['attestation_format' => 'none']);
    }

    public function rs256(): self
    {
        return $this->state(fn (): array => ['attestation_format' => 'none']);
    }

    public function forAuthenticatable(Model $model): self
    {
        return $this->state(fn (): array => [
            'authenticatable_type' => $model->getMorphClass(),
            'authenticatable_id' => $model->getKey(),
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
