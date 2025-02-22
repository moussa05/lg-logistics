<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use App\Http\Resources\UserResource;
use Laravel\Pail\ValueObjects\Origin\Console;
use Laravel\Sanctum\HasApiTokens;

class AuthController extends Controller
{

    public function getUser(Request $request)
    {
        // Vérification du numéro de téléphone fourni
        $request->validate([
            'phone_number' => 'required|string',
        ]);

        // Recherche de l'utilisateur
        $user = User::where('phone_number', $request->phone_number)->first();

        if (!$user) {
            return response()->json([
                'message' => 'Utilisateur non trouvé'
            ], 404);
        }

        // Retourner les informations de l'utilisateur
        return response()->json([
            'first_name' => $user->first_name,
            'last_name' => $user->last_name,
            'phone_number' => $user->phone_number,
            'email' => $user->email,
            'status' => $user->status,
        ], 200);
    }
    // ✅ Étape 1 : Enregistrer le numéro et envoyer OTP
    public function sendOtp(Request $request)
    {
    
        $validated = Validator::make($request->all(), [
            'phone_number' => 'required|unique:users,phone_number',
        ]);

        if ($validated->fails()) {
            return response()->json(['error' => $validated->errors()], 422);
        }

        // 📝 Stocker l'utilisateur en "pending"
        $user = User::updateOrCreate(
            ['phone_number' => $request->phone_number],
            ['status' => 'pending']
        );

        return response()->json([
            'message' => 'Numéro enregistré. Attente vérification OTP.',
            'user' => new UserResource($user),
        ]);
    }

    // ✅ Étape 2 : Vérifier l'OTP et finaliser l'inscription
    public function verifyOtp(Request $request)
    {
        $validated = Validator::make($request->all(), [
            'phone_number' => 'required|exists:users,phone_number',
            'first_name' => 'required|string',
            'last_name' => 'required|string',
        ]);

        if ($validated->fails()) {
            return response()->json(['error' => $validated->errors()], 422);
        }

        $user = User::where('phone_number', $request->phone_number)->first();
        
        if (!$user) {
            return response()->json(['error' => 'Utilisateur non trouvé'], 404);
        }

        // 📝 Mettre à jour le profil après validation OTP
        $user->update([
            'first_name' => $request->first_name,
            'last_name' => $request->last_name,
            'status' => 'active',
            'password' => Hash::make(Str::random(10)), // Mot de passe temporaire
        ]);

        // ✅ Générer un token Sanctum
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'message' => 'Inscription réussie',
            'token' => $token,
            'user' => new UserResource($user),
        ]);
    }

    // ✅ Déconnexion
    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();
        return response()->json(['message' => 'Déconnexion réussie']);
    }
}
