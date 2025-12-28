<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class ServiceSeeder extends Seeder
{
    public function run(): void
    {
        DB::table('services')->insert([
            [
                'name' => 'Course',
                'img_path' => 'services/course.png',
                'actif' => 'oui',
                'starting_price' =>1000,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'name' => 'Conteneur',
                'img_path' => 'services/conteneur.png',
                'actif' => 'oui',
                'starting_price' => 22000,
                'created_at' => now(),
                'updated_at' => now(),
            ]
            ,
            [
                'name' => 'VTC',
                'img_path' => 'services/vtc.png',
                'actif' => 'non',
                'starting_price' => 1500,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'name' => 'Déménagement',
                'img_path' => 'services/demenagement.png',
                'actif' => 'oui',
                'starting_price' => 15000,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            
            [
                'name' => 'Fret',
                'img_path' => 'services/fret.png',
                'actif' => 'oui',
                'starting_price' => 30.00,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'name' => 'Camion plateau',
                'img_path' => 'services/camion.png',
                'actif' => 'oui',
                'starting_price' => 12000,
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ]);
    }
}