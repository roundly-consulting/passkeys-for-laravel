# Shipped attestation trust anchors

Roots this package trusts by default, one directory per WebAuthn attestation format.
They are loaded by `RoundlyConsulting\Passkeys\Attestation\AttestationAnchors` when
`passkeys.attestation_anchors.defaults` is `true` (the default), and ignored entirely
when it is `false`.

Every certificate here was fetched from its vendor's own published source and its
SHA-256 fingerprint is pinned as a literal in
`tests/Unit/Attestation/AttestationAnchorsTest.php`. Nothing is trusted that cannot
be verified against the vendor's publication.

## `apple/` — Apple anonymous attestation (WebAuthn §8.8)

Source: <https://www.apple.com/certificateauthority/private/> — the *Apple WebAuthn
Root CA*, published at
<https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem>. It is **not**
Apple's App Attest root, nor an App Store root.

| File | Subject | Key | SHA-256 (DER) |
|---|---|---|---|
| `apple-webauthn-root-ca.pem` | `CN=Apple WebAuthn Root CA, O=Apple Inc., ST=California` | EC P-384 | `0915dd5c07a28db549d1f677bb5a75d4bfbe9561a773424327762e9e02f9bb29` |

Apple's `x5c` always omits the root, so this anchor completes the chain rather than
appearing in it — the anchor store's *anchored-by-completion* mode.

## `android-key/` — Google hardware attestation

Source: <https://developer.android.com/privacy-and-security/security-key-attestation>
(the "root certificates" section of Google's own Android documentation).

| File | Subject | Key | SHA-256 (DER) |
|---|---|---|---|
| `google-hardware-attestation-2016.pem` | `serialNumber=f92009e853b6b045` | RSA-4096 | `c1984a3ef45c1e2a918551de10603c86f7051b2249c4891cae3230eabd0c97d5` |
| `google-hardware-attestation-2019.pem` | `serialNumber=f92009e853b6b045` | RSA-4096 | `1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc` |
| `google-hardware-attestation-2021.pem` | `serialNumber=f92009e853b6b045` | RSA-4096 | `ab6641178a36e179aa0c1cdddf9a16eb45fa20943e2b8cd7c7c05c26cf8b487a` |
| `google-hardware-attestation-2022.pem` | `serialNumber=f92009e853b6b045` | RSA-4096 | `cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc` |
| `google-key-attestation-ca1-2025.pem` | `CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US` | EC P-384 | `6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0` |

Google publishes several generations of the root and signs different device fleets
under different ones, so all of them are trusted. The `android-key` verifier itself
is not built yet — these anchors are inert until it lands, and a host may already
point `passkeys.attestation_anchors.paths.android-key` at its own list instead.

## Formats with no shipped default

`packed` (and, later, `tpm`) attest under vendor-specific roots — there is no single
publisher to ship. Supply your security-key vendor's PEM via
`passkeys.attestation_anchors.paths.packed`.
