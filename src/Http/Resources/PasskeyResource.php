<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * A display-safe serialisation of a stored passkey. It exposes only the fields a
 * "your passkeys" screen needs — never the COSE public key, the discoverable-login
 * user handle, or the internal credential-id lookup keys.
 *
 * @mixin Passkey
 */
final class PasskeyResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'aaguid' => $this->aaguid,
            'transports' => $this->transports,
            'backup_eligible' => $this->backup_eligible,
            'backup_state' => $this->backup_state,
            'last_used_at' => $this->last_used_at?->toIso8601String(),
            'created_at' => $this->created_at?->toIso8601String(),
        ];
    }
}
