<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class ServiceSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Services principaux
        DB::table('services')->insert([
            [
                'name' => 'Course',
                'img_path' => 'services/course.png',
                'actif' => 'oui',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'name' => 'VTC',
                'img_path' => 'services/vtc.png',
                'actif' => 'oui',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'name' => 'Déménagement',
                'img_path' => 'services/demenagement.png',
                'actif' => 'oui',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'name' => 'Voir plus',
                'img_path' => 'services/plus.png',
                'actif' => 'oui',
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ]);

        // Services additionnels
        DB::table('services')->insert([
            [
                'name' => 'Fret',
                'img_path' => 'services/fret.png',
                'actif' => 'oui',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'name' => 'Conteneur',
                'img_path' => 'services/conteneur.png',
                'actif' => 'oui',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'name' => 'Camion plateau',
                'img_path' => 'services/camion.png',
                'actif' => 'oui',
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ]);
    }
}