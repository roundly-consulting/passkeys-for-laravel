<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The host-owned `users` and `clients` tables the credentials hang off. They stand in for
 * tables a host owns — including the opaque handle column `passkeys.user.handle_column`
 * names — so they are built here rather than shipped.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->string('passkey_user_handle')->nullable();
            $table->timestamps();
        });

        // A second guard's account table, so ownership checks can prove the owner TYPE
        // matters when two owners share a key. Its handle column comes from the shipped
        // `passkeyUserHandle()` macro, so every engine leg (sqlite AND pgsql) builds it.
        Schema::create('clients', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->passkeyUserHandle();
            $table->timestamps();
        });
    }
};
