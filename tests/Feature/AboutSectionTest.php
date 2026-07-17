<?php

declare(strict_types=1);

/**
 * The secret-safe `about` capture (A).
 *
 * Purchases #13 is the bug this exists for: the fleet's most credential-heavy `about`
 * section was guarded by negative assertions against `app(Kernel::class)->output()`, which
 * returns `''`. Every "does not leak" check was vacuous — passing against empty output.
 *
 * Passkeys' section is written to report the *shape* of the ceremony policy — counts,
 * toggles, bounds — and never host topology. The two real risks here are an absolute
 * filesystem path to a trust-anchor PEM (which maps the host's disk) and the AAGUID
 * allow-list (which fingerprints exactly which authenticator models an org issues). Both are
 * reported by count.
 *
 * `mustRender` is required and non-empty, so the negative half can never pass over empty
 * output, and its entries deliberately do not overlap the secret surface.
 */
it('renders the passkeys section without leaking anchors or aaguids', function (): void {
    config()->set('passkeys.attestation_anchors.paths', [
        'packed' => ['/srv/secrets/webauthn/acme-fido-root.pem'],
    ]);
    config()->set('passkeys.aaguids.allowed', [
        'd8522d9f-575b-4866-88a9-ba99fa02f35b',
        'ee882879-721c-4913-9775-3dfcce97072a',
    ]);

    expect('passkeys')->toLeakNoSecrets(
        secrets: [
            // Host topology — an absolute path on the host's filesystem.
            '/srv/secrets/webauthn/acme-fido-root.pem',
            'acme-fido-root.pem',

            // The AAGUID allow-list fingerprints the exact authenticator models an
            // organisation issues. Reported as a count, never enumerated.
            'd8522d9f-575b-4866-88a9-ba99fa02f35b',
            'ee882879-721c-4913-9775-3dfcce97072a',
        ],
        mustRender: [
            // The positive proof the section reports rather than sitting empty.
            'Model',
            'Relying party',
            'Origins',
            'Algorithms',
            'User verification',
            'Sign-count policy',
            // The count-not-entries lines really render their counts — which is what makes
            // hiding the entries meaningful rather than accidental.
            '1 host path(s)',
            '2 allowed',
        ],
    );
});
