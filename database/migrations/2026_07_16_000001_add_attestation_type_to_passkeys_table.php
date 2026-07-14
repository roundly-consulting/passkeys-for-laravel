<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Purely additive. Rows registered before attestation types existed stay
        // null — an honest value, not a guess. No existing column is touched:
        // credential_id (unpadded base64url) and public_key (padded base64) are
        // what every authenticator's other half is bound to.
        $name = config('passkeys.table');

        Schema::table(is_string($name) ? $name : 'passkeys', function (Blueprint $table): void {
            $table->string('attestation_type', 16)->nullable()->after('attestation_format');
        });
    }
};
