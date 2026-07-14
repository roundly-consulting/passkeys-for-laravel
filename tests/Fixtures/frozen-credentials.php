<?php

declare(strict_types=1);

/*
 * FROZEN at-rest credential vectors.
 *
 * These bytes were produced by the PRE-RETROFIT implementation — the package's own
 * Support\Base64Url + base64_encode + hash('sha256') — before passkeys was rebuilt on
 * crypto-for-laravel, and they are asserted byte-for-byte afterwards.
 *
 * They are the lock-out guard. A passkey already sitting in a host's database keeps
 * its exact credential_id, credential_id_hash and public_key encoding, and a real
 * assertion signed by that credential still verifies. Never "fix" these values: if a
 * change makes them fail, that change would have locked every registered user out of
 * their account — the authenticator holds the other half of the key pair and there is
 * no migration back.
 */

return [
    'rp_id' => 'example.com',
    'origin' => 'https://example.com',
    'challenge' => 'KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio',
    'user_handle' => 'XFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFw',

    // The raw 20-byte credential id an authenticator minted.
    'credential_id_raw_hex' => 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',

    // …and the three columns the pre-retrofit write path stored it as.
    'stored_credential_id' => 'obLD1OX2BxgpOktcbX6PkBI0Vng',
    'stored_credential_id_hash' => 'de6f906585dc76206169be3795b2325c4c0dca689dbc4aa4202f10cdaba2da1c',

    // A genuine assertion over this challenge, from that credential.
    'client_data_json' => '{"type":"webauthn.get","challenge":"KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio","origin":"https:\\/\\/example.com","crossOrigin":false}',
    'authenticator_data_hex' => 'a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce19470500000007',

    'algorithms' => [

        // ES256 (COSE -7) — the signature is ASN.1 DER, as authenticators deliver it.
        'es256' => [
            'cose_hex' => 'a501020326200121582009446babd71b594a75ed499a866c12bc3d169956a6fd4a47a0c9'.
                '30b1c737fa6722582022e5930bcef8015d0807aca5243c8d72652ef5bbe225f5995029d5'.
                '2a8bc1c097',
            'stored_public_key' => 'pQECAyYgASFYIAlEa6vXG1lKde1JmoZsErw9FplWpv1KR6DJMLHHN/pnIlggIuWTC874AV0I'.
                'B6ylJDyNcmUu9bviJfWZUCnVKovBwJc=',
            'signature_hex' => '3044022048302016d0e9f2adadef6a54586359339ffb5a785f16d9dccccb0d4f233b997c'.
                '022076f371d624b04446e0a8d905de2624815d9074ddb4411e2ad085a64e3e3f4524',
        ],

        // RS256 (COSE -257) — RSA-2048, e=65537.
        'rs256' => [
            'cose_hex' => 'a401030339010020590100be06e1f6e844be91cd90082f969c36a56369a966a12fd936c8'.
                '963b7c1634147cd7a53768af3612785a7445eab5fffde1593760e1256ac382d1109de34b'.
                '902782383d9799b643219ae36e09ef64c898bd75bac56dd2836769b4f18d5bc666aba4c2'.
                'f0943840660779160d2003c40490fceadfc4de3c3c29d671e5a01655f96ba28ee9645506'.
                '60354687e1b3559404f8a0a425d03c7d7ed1ade4a1277b1ab2f1265eb25786c8fe1e306e'.
                '63786bcf156069e52b8043cc47fdf7b636fd9a9b344eb7c8ef9844e7819cdc63f7cfc2b2'.
                'aa89aa0222e3745e048f7923324f2d205a79071de4672a8899568f9e84b1325e52633c84'.
                '066407db8668de761268071be065392143010001',
            'stored_public_key' => 'pAEDAzkBACBZAQC+BuH26ES+kc2QCC+WnDalY2mpZqEv2TbIljt8FjQUfNelN2ivNhJ4WnRF'.
                '6rX//eFZN2DhJWrDgtEQneNLkCeCOD2XmbZDIZrjbgnvZMiYvXW6xW3Sg2dptPGNW8Zmq6TC'.
                '8JQ4QGYHeRYNIAPEBJD86t/E3jw8KdZx5aAWVflroo7pZFUGYDVGh+GzVZQE+KCkJdA8fX7R'.
                'reShJ3sasvEmXrJXhsj+HjBuY3hrzxVgaeUrgEPMR/33tjb9mps0TrfI75hE54Gc3GP3z8Ky'.
                'qomqAiLjdF4Ej3kjMk8tIFp5Bx3kZyqImVaPnoSxMl5SYzyEBmQH24Zo3nYSaAcb4GU5IUMB'.
                'AAE=',
            'signature_hex' => '444e21239e34173a9e70cf665242310a802d54af1c550939fec19b1c19a8f405d2f6a05e'.
                '15bb788a1b7f13d9fc78a764cc09b73db386f3d38aa4081ae150da850648b60236f164b4'.
                'c4d45a6fa94c0f0a85d5b6ce6438e99e7a0045b178ed9ac3f75394325d69392c821b2aaf'.
                'a166652dbdc936370dd3c39becae6788da3d7ae87d9b561a37b2bdd5155f82775f347e94'.
                '3fea8c7634cb3da85de1629822d7053e21c4dfde27f38fde6682b31f3dad20334ae876ab'.
                '5401f84f212f6220d890f23650f7254095d50ba4e10562b1b0d017d6776795c4628d8f8f'.
                'd2b05b46db8ce0ed17172ad4e6baa087d4cccae3e9e6e7762e20ff3242c5cf1d883395c7'.
                '7b97f1d3',
        ],

        // EdDSA (COSE -8) — Ed25519, raw 64-byte signature.
        'eddsa' => [
            'cose_hex' => 'a40101032720062158203a04d5926b49b098560924ce73f1becb3c9439c338f0f03571ce'.
                'dfd6ed197cb5',
            'stored_public_key' => 'pAEBAycgBiFYIDoE1ZJrSbCYVgkkznPxvss8lDnDOPDwNXHO39btGXy1',
            'signature_hex' => 'd08b26ba83e2990890e270ba70373793b6166ead849078fb84864d076d3f8b03c59a673b'.
                '37b46122fe957185c8a4fd8a1ebf3f9f6d4be338b413923f648b1a0f',
        ],
    ],

];
