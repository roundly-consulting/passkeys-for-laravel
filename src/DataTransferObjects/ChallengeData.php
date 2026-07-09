<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use RoundlyConsulting\Passkeys\Enums\UserVerification;

/**
 * The server-side context stored for an in-flight ceremony, keyed by a random
 * ceremony id. Held single-use in the challenge store until the response lands.
 *
 * @param  list<int>  $algorithms
 */
final readonly class ChallengeData
{
    /**
     * @param  list<int>  $algorithms
     */
    public function __construct(
        public string $challenge,
        public UserVerification $userVerification,
        public array $algorithms,
        public ?string $userHandle = null,
    ) {}

    /**
     * @return array{challenge: string, user_verification: string, algorithms: list<int>, user_handle: string|null}
     */
    public function toArray(): array
    {
        return [
            'challenge' => $this->challenge,
            'user_verification' => $this->userVerification->value,
            'algorithms' => $this->algorithms,
            'user_handle' => $this->userHandle,
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

        $userHandle = $data['user_handle'] ?? null;

        return new self(
            challenge: is_string($data['challenge'] ?? null) ? $data['challenge'] : '',
            userVerification: UserVerification::from(is_string($data['user_verification'] ?? null) ? $data['user_verification'] : 'preferred'),
            algorithms: $algorithms,
            userHandle: is_string($userHandle) ? $userHandle : null,
        );
    }
}
