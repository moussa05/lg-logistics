<?php

namespace App\Http\Controllers;

use App\Models\Commande;
use Illuminate\Http\Request;

class CommandeController extends Controller
{
    public function index()
    {
        $commandes = Commande::with(['user', 'service'])->get();
        return response()->json($commandes);
    }

    public function store(Request $request)
    {
        $request->validate([
            'id_user' => 'required|exists:users,id',
            'id_service' => 'required|exists:services,id',
            'point_depart' => 'nullable|string',
            'destination' => 'nullable|string',
            'moyen_de_paiement' => 'nullable|string',
            'contact' => 'nullable|string',
            'commentaires' => 'nullable|string',
        ]);

        $commande = Commande::create($request->all());

        return response()->json($commande, 201);
    }

    public function show(Commande $commande)
    {
        return response()->json($commande->load(['user', 'service']));
    }

    public function update(Request $request, Commande $commande)
    {
        $request->validate([
            'point_depart' => 'sometimes|string',
            'destination' => 'sometimes|string',
            'moyen_de_paiement' => 'sometimes|string',
            'contact' => 'sometimes|string',
            'commentaires' => 'nullable|string',
        ]);

        $commande->update($request->all());

        return response()->json($commande);
    }

    public function destroy(Commande $commande)
    {
        $commande->delete();
        return response()->json(['message' => 'Commande supprimée']);
    }
}
