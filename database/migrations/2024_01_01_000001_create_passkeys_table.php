<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // The table name is config-driven (`passkeys.table`, which the model reads):
        // a host that renames it must get the table it configured, not a `passkeys`
        // table its model will never look at.
        $name = config('passkeys.table');

        Schema::create(is_string($name) ? $name : 'passkeys', function (Blueprint $table): void {
            $table->id();
            $table->morphs('authenticatable');
            // A roaming security key's credential id can reach ~1364 base64url
            // chars (spec allows up to 1023 raw bytes), which overflows a
            // varchar(255). Store it as text and key the unique index on a
            // fixed-length sha-256 hash so it fits every database's limit.
            $table->text('credential_id');
            $table->char('credential_id_hash', 64)->unique();
            $table->text('public_key');
            $table->string('user_handle')->index();
            $table->jsonb('transports')->nullable();
            $table->uuid('aaguid')->nullable();
            $table->unsignedBigInteger('sign_count')->default(0);
            $table->string('name')->nullable();
            $table->string('attestation_format')->nullable();
            $table->boolean('backup_eligible')->default(false);
            $table->boolean('backup_state')->default(false);
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();
            $table->softDeletes();
        });
    }
};
