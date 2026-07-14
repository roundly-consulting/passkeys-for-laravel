<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use RoundlyConsulting\Crypto\Codec\Base64Url;

/**
 * A PublicKeyCredentialDescriptor for the allow/exclude credential lists.
 */
final readonly class CredentialDescriptor
{
    /**
     * @param  string  $id  raw credential id bytes
     * @param  list<string>  $transports
     */
    public function __construct(
        public string $id,
        public array $transports = [],
    ) {}

    /**
     * @return array{type: string, id: string, transports?: list<string>}
     */
    public function toArray(): array
    {
        $descriptor = [
            'type' => 'public-key',
            'id' => Base64Url::encode($this->id),
        ];

        if ($this->transports !== []) {
            $descriptor['transports'] = $this->transports;
        }

        return $descriptor;
    }
}
