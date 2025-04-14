<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class BannerSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        DB::table('banners')->insert([
            [
                'name' => 'Promotion Coursiers',
                'path' => 'banners/coursier_promo.jpg',
                'actif' => 'oui',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'name' => 'Offre Spéciale VTC',
                'path' => 'banners/vtc_special.jpg',
                'actif' => 'oui',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'name' => 'Déménagement à -20%',
                'path' => 'banners/demenagement_promo.jpg',
                'actif' => 'oui',
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ]);
    }
}