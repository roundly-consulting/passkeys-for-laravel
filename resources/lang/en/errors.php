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
    'expectation_unsaved_owner' => 'A passkey owner expectation needs a persisted owner.',
    'malformed_cbor' => 'The CBOR data is malformed.',
    'invalid_cose_key' => 'The COSE public key is invalid.',
    'user_verification_required' => 'User verification was required but not performed.',
    'missing_rp_id' => 'A relying party identifier (passkeys.rp.id) must be configured.',
    'empty_origins' => 'At least one allowed origin (passkeys.origins) must be configured.',
    'unsupported_configured_algorithm' => 'The COSE algorithm ":alg" is not one this relying party accepts (ES256, RS256, EdDSA).',

    // Attestation — configuration.
    'attestation_conveyance_mismatch' => 'passkeys.attestation_trust is ":trust" but passkeys.attestation is "none", so authenticators are told not to attest and every registration would be refused. Set passkeys.attestation to "direct" (PASSKEYS_ATTESTATION=direct).',
    'attestation_invalid_clock_skew' => 'passkeys.attestation_clock_skew must be between 0 and :max seconds; ":seconds" was configured.',
    'attestation_unreadable_anchor' => 'The trust anchor ":path" configured in passkeys.attestation_anchors.paths.:format cannot be read or does not contain a PEM certificate.',

    // Attestation — the statement's maths failed.
    'attestation_malformed_statement' => 'The ":format" attestation statement is malformed: :reason.',
    'attestation_signature_mismatch' => 'The ":format" attestation signature could not be verified.',
    'attestation_algorithm_mismatch' => 'The ":format" attestation statement claims COSE algorithm :claimed but its signing key is :actual.',
    'attestation_aaguid_mismatch' => 'The attestation certificate\'s AAGUID does not match the one in the authenticator data.',
    'attestation_credential_key_mismatch' => 'The ":format" attestation certificate certifies a different public key than the credential being registered.',
    'attestation_apple_nonce_mismatch' => 'The Apple attestation certificate\'s nonce is not the hash of this ceremony\'s authenticator data and client data, so the statement does not attest this registration.',
    'attestation_certificate_requirement' => 'The ":format" attestation certificate does not meet a WebAuthn requirement: :requirement.',
    'attestation_ecdaa_unsupported' => 'The ":format" attestation statement uses ECDAA, which WebAuthn Level 3 removed and this relying party never accepts.',

    // Attestation — policy refused it.
    'unsupported_attestation_format' => 'Attestation format ":format" is not supported. Supported formats: :supported.',
    'attestation_statement_missing' => 'passkeys.attestation_trust is ":trust" but the authenticator sent a ":format" statement, which proves nothing. Set passkeys.attestation to "direct" and use an authenticator that attests.',
    'attestation_root_not_anchored' => 'The ":format" attestation chain\'s root (":subject", sha256 :fingerprint…) is not among the configured trust anchors. Add its PEM to passkeys.attestation_anchors.paths.:format.',
    'attestation_no_anchors' => 'No trust anchors are configured for ":format" attestation. Set passkeys.attestation_anchors.paths.:format.',
    'attestation_self_rejected' => 'attestation_trust "basic" does not accept self-attestation; the ":format" statement presented no attestation certificate.',
    'attestation_chain_not_linked' => 'The ":format" attestation certificate chain is not linked: a certificate is not signed by the one above it.',
    'attestation_certificate_expired' => 'The attestation certificate ":subject" expired at :not_after (clock skew :leeway s).',
    'attestation_certificate_not_yet_valid' => 'The attestation certificate ":subject" is not valid until :not_before (clock skew :leeway s).',
    'attestation_aaguid_not_allowed' => 'The authenticator AAGUID ":aaguid" is not in passkeys.aaguids.allowed.',
];
