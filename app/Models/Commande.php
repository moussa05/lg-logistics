<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class Commande extends Model
{
    use HasFactory;

    protected $fillable = [
        'id_user',
        'id_service',
        'point_depart',
        'destination',
        'moyen_de_paiement',
        'contact',
        'commentaires',
    ];

    public function user()
    {
        return $this->belongsTo(User::class, 'id_user');
    }

    public function service()
    {
        return $this->belongsTo(Service::class, 'id_service');
    }
}
