<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('passkeys', function (Blueprint $table): void {
            $table->id();
            $table->morphs('authenticatable');
            $table->string('credential_id')->unique();
            $table->text('public_key');
            $table->string('user_handle')->index();
            $table->json('transports')->nullable();
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
