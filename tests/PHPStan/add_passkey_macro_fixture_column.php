<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\ColumnDefinition;
use Illuminate\Support\Facades\Schema;

/**
 * Static-analysis fixture (never executed): a host migration calling the schema macro, analysed
 * by `composer analyse` so the macro stays visible to Larastan without a booted provider.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $this->column($table->passkeyUserHandle());
        });

        Schema::create('passkey_macro_fixtures', function (Blueprint $table): void {
            $table->id();
            $table->passkeyUserHandle()->comment('WebAuthn user handle');
        });
    }

    private function column(ColumnDefinition $column): void
    {
        $column->after('email');
    }
};
