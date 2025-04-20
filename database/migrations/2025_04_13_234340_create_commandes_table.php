<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
            Schema::create('commandes', function (Blueprint $table) {
                $table->id();
                $table->foreignId('id_user')->constrained('users')->onDelete('cascade');
                $table->foreignId('id_service')->constrained('services')->onDelete('cascade');
                $table->string('point_depart');
                $table->string('destination');
                $table->string('moyen_de_paiement');
                $table->string('contact');
                $table->text('commentaires')->nullable();
                $table->timestamps();
            });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('commandes');
    }
};
