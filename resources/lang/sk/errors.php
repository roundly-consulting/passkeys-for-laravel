<?php

declare(strict_types=1);

return [
    'invalid_client_data' => 'Údaje klienta nie sú platné.',
    'invalid_authenticator_data' => 'Údaje autentifikátora nie sú platné.',
    'user_presence_missing' => 'Autentifikátor nepotvrdil prítomnosť používateľa.',
    'backup_state_inconsistent' => 'Príznaky stavu zálohy poverenia si navzájom odporujú.',
    'backup_eligibility_changed' => 'Autentifikátor nahlásil inú spôsobilosť na zálohovanie (príznak BE), než s akou bolo poverenie zaregistrované; spôsobilosť poverenia na zálohovanie sa nikdy nemení.',
    'attested_data_missing' => 'V odpovedi na registráciu chýbajú atestované údaje poverenia.',
    'challenge_mismatch' => 'Výzva sa nezhoduje s výzvou vydanou pre túto ceremóniu.',
    'challenge_user_mismatch' => 'Výzva bola vydaná pre iného používateľa.',
    'challenge_ceremony_type' => 'Výzva bola vydaná pre iný typ ceremónie.',
    'challenge_expired' => 'Výzva už vypršala alebo bola použitá.',
    'origin_mismatch' => 'Pôvod (origin) ceremónie nie je povolený.',
    'cross_origin_forbidden' => 'Ceremónie z iného pôvodu (cross-origin) nie sú povolené.',
    'rp_id_mismatch' => 'Hash identifikátora spoliehajúcej sa strany (RP ID) sa nezhoduje.',
    'signature_invalid' => 'Podpis sa nepodarilo overiť.',
    'sign_count_regression' => 'Počítadlo podpisov sa nezvýšilo.',
    'unsupported_algorithm' => 'Algoritmus poverenia nie je podporovaný.',
    'credential_already_registered' => 'Tento prístupový kľúč je už zaregistrovaný.',
    'credential_not_found' => 'Nenašiel sa žiadny zodpovedajúci prístupový kľúč.',
    'expectation_unsaved_owner' => 'Očakávanie vlastníka prístupového kľúča vyžaduje vlastníka uloženého v databáze.',
    'malformed_cbor' => 'Údaje CBOR majú neplatný formát.',
    'invalid_cose_key' => 'Verejný kľúč COSE nie je platný.',
    'user_verification_required' => 'Overenie používateľa sa vyžadovalo, ale nevykonalo sa.',
    'missing_rp_id' => 'Je potrebné nastaviť identifikátor spoliehajúcej sa strany (passkeys.rp.id).',
    'empty_origins' => 'Je potrebné nastaviť aspoň jeden povolený pôvod (passkeys.origins).',
    'unsupported_configured_algorithm' => 'Táto spoliehajúca sa strana neprijíma algoritmus COSE „:alg“ (prijíma ES256, RS256, EdDSA).',

    // Attestation — configuration.
    'attestation_conveyance_mismatch' => 'passkeys.attestation_trust je „:trust“, ale passkeys.attestation je „none“, takže autentifikátory dostanú pokyn atestáciu neposielať a každá registrácia by bola odmietnutá. Nastavte passkeys.attestation na „direct“ (PASSKEYS_ATTESTATION=direct).',
    'attestation_invalid_clock_skew' => 'passkeys.attestation_clock_skew musí byť od 0 do :max sekúnd; nastavená hodnota je „:seconds“.',
    'invalid_config_value' => 'passkeys.:key musí byť :expected; nastavená hodnota je :given.',
    'attestation_unreadable_anchor' => 'Kotva dôvery „:path“ nastavená v passkeys.attestation_anchors.paths.:format sa nedá prečítať alebo neobsahuje certifikát PEM.',

    // Attestation — the statement's maths failed.
    'attestation_malformed_statement' => 'Atestačné vyhlásenie „:format“ je chybne zostavené: :reason.',
    'attestation_signature_mismatch' => 'Podpis atestácie „:format“ sa nepodarilo overiť.',
    'attestation_algorithm_mismatch' => 'Atestačné vyhlásenie „:format“ uvádza algoritmus COSE :claimed, ale jeho podpisový kľúč je :actual.',
    'attestation_aaguid_mismatch' => 'AAGUID v atestačnom certifikáte sa nezhoduje s AAGUID v údajoch autentifikátora.',
    'attestation_credential_key_mismatch' => 'Atestačný certifikát „:format“ osvedčuje iný verejný kľúč, než má registrované poverenie.',
    'attestation_apple_nonce_mismatch' => 'Hodnota nonce v atestačnom certifikáte Apple nie je hashom údajov autentifikátora a údajov klienta tejto ceremónie, preto vyhlásenie neatestuje túto registráciu.',
    'attestation_certificate_requirement' => 'Atestačný certifikát „:format“ nespĺňa požiadavku WebAuthn: :requirement.',
    'attestation_ecdaa_unsupported' => 'Atestačné vyhlásenie „:format“ používa ECDAA, ktoré bolo z WebAuthn Level 3 odstránené a táto spoliehajúca sa strana ho nikdy neprijíma.',

    // Attestation — policy refused it.
    'unsupported_attestation_format' => 'Formát atestácie „:format“ nie je podporovaný. Podporované formáty: :supported.',
    'attestation_statement_missing' => 'passkeys.attestation_trust je „:trust“, ale autentifikátor poslal vyhlásenie „:format“, ktoré nič nepreukazuje. Synchronizované prístupové kľúče (iCloud Keychain, Google Password Manager, väčšina správcov hesiel) nikdy neatestujú, nech sa požaduje čokoľvek: pri tomto nastavení sa môžu zaregistrovať iba autentifikátory viazané na zariadenie, napríklad bezpečnostné kľúče alebo spravované zariadenia — ak chcete prijímať aj synchronizované kľúče, nastavte passkeys.attestation_trust na „ignore“. Ak táto ceremónia požadovala atestáciu „none“, požadujte namiesto nej „direct“.',
    'attestation_root_not_anchored' => 'Koreňový certifikát atestačného reťazca „:format“ („:subject“, sha256 :fingerprint…, vydavateľ „:issuer“) nie je medzi nastavenými kotvami dôvery. Pridajte PEM vydávajúcej certifikačnej autority do passkeys.attestation_anchors.paths.:format.',
    'attestation_no_anchors' => 'Pre atestáciu „:format“ nie sú nastavené žiadne kotvy dôvery; vydavateľom tohto reťazca je „:issuer“. Pridajte PEM tejto certifikačnej autority do passkeys.attestation_anchors.paths.:format.',
    'attestation_self_rejected' => 'attestation_trust „basic“ neprijíma samoatestáciu; vyhlásenie „:format“ nepredložilo žiadny atestačný certifikát.',
    'attestation_issuer_not_ca' => 'Atestačný reťazec „:format“ nie je platná certifikačná cesta: „:subject“ v ňom podpísal certifikát, ale nie je certifikačnou autoritou (potrebuje basicConstraints CA:TRUE a, ak má rozšírenie keyUsage, aj keyCertSign).',
    'attestation_path_length_exceeded' => 'Atestačný reťazec „:format“ nie je platná certifikačná cesta: maximálny počet sprostredkujúcich certifikátov pod „:subject“ je :limit (basicConstraints pathLenConstraint), no reťazec ich obsahuje viac.',
    'attestation_chain_not_linked' => 'Reťazec atestačných certifikátov „:format“ nie je prepojený: niektorý certifikát nie je podpísaný certifikátom nad ním.',
    'attestation_certificate_expired' => 'Platnosť atestačného certifikátu „:subject“ vypršala :not_after (tolerancia odchýlky hodín :leeway s).',
    'attestation_certificate_not_yet_valid' => 'Atestačný certifikát „:subject“ je platný až od :not_before (tolerancia odchýlky hodín :leeway s).',
    'attestation_aaguid_not_allowed' => 'AAGUID autentifikátora „:aaguid“ nie je v zozname passkeys.aaguids.allowed.',
];
