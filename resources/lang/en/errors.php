<?php

declare(strict_types=1);

return [
    'invalid_client_data' => 'The client data is invalid.',
    'invalid_authenticator_data' => 'The authenticator data is invalid.',
    'user_presence_missing' => 'The authenticator did not assert user presence.',
    'backup_state_inconsistent' => 'The credential backup-state flags are inconsistent.',
    'attested_data_missing' => 'The registration response is missing attested credential data.',
    'challenge_mismatch' => 'The challenge does not match the one issued for this ceremony.',
    'challenge_user_mismatch' => 'The challenge was issued for a different user.',
    'challenge_ceremony_type' => 'The challenge was issued for a different ceremony type.',
    'challenge_expired' => 'The challenge has expired or was already used.',
    'origin_mismatch' => 'The ceremony origin is not allowed.',
    'cross_origin_forbidden' => 'Cross-origin ceremonies are not permitted.',
    'rp_id_mismatch' => 'The relying party identifier hash does not match.',
    'signature_invalid' => 'The signature could not be verified.',
    'sign_count_regression' => 'The signature counter did not advance.',
    'unsupported_algorithm' => 'The credential algorithm is not supported.',
    'credential_already_registered' => 'This credential is already registered.',
    'credential_not_found' => 'No matching passkey could be found.',
    'malformed_cbor' => 'The CBOR data is malformed.',
    'invalid_cose_key' => 'The COSE public key is invalid.',
    'user_verification_required' => 'User verification was required but not performed.',
    'missing_rp_id' => 'A relying party identifier (passkeys.rp.id) must be configured.',
    'empty_origins' => 'At least one allowed origin (passkeys.origins) must be configured.',
    'unsupported_attestation_trust' => 'The ":trust" attestation trust level is not supported; only "ignore" is available.',
    'unsupported_configured_algorithm' => 'The COSE algorithm ":alg" is not one this relying party accepts (ES256, RS256, EdDSA).',
];
