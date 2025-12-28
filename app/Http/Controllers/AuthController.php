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
use Carbon\Carbon;
use App\Models\Otp;
use App\Services\TwilioService;

class AuthController extends Controller
{

    public function generateOtp($userId)
    {
        // invalider les anciens OTP
        Otp::where('user_id', $userId)
            ->where('is_used', false)
            ->update(['is_used' => true]);

        $otp = rand(100000, 999999);

        return Otp::create([
            'user_id' => $userId,
            'code' => $otp,
            'expires_at' => Carbon::now()->addMinutes(5), // valable 5 min
        ]);
    }
    function verifOtp($userId, $code)
    {
        $otp = Otp::where('user_id', $userId)
            ->where('code', $code)
            ->where('is_used', false)
            ->first();

        if (!$otp) {
            return false;
        }

        if (Carbon::now()->greaterThan($otp->expires_at)) {
            return false;
        }

        // Marquer comme utilisé
        $otp->update(['is_used' => true]);

        return true;
    }

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

        // ✅ Générer un token Sanctum
        $token = $user->createToken('auth_token')->plainTextToken;

        // Retourner l'utilisateur + le token
        return response()->json([
            'message' => 'Utilisateur trouvé',
            'user' => new UserResource($user),
            'token' => $token,
        ], 200);
    }

    // ✅ Étape 1 : Enregistrer le numéro et envoyer OTP
    public function sendOtp(Request $request)
    {

        $validated = Validator::make($request->all(), [
            'phone_number' => 'required',
        ]);

        if ($validated->fails()) {
            return response()->json(['error' => $validated->errors()], 422);
        }

        // 📝 Stocker l'utilisateur en "pending"
        $user = User::updateOrCreate(
            ['phone_number' => $request->phone_number],
            ['status' => 'pending']
        );

        $otp = $this->generateOtp($user->id);
        TwilioService::sendOtp($user->phone_number, $otp->code);

        return response()->json([
            'message' => 'Numéro enregistré. Attente vérification OTP.',
            'user' => new UserResource($user),
        ]);
    }

    // ✅ Étape 2 : Vérifier l'OTP et finaliser l'inscription
    public function verifyOtp(Request $request)
    {
        $validated = Validator::make($request->all(), [
            'phone_number' => 'required',
            'code' => 'required'
        ]);

        if ($validated->fails()) {
            return response()->json(['error' => $validated->errors()], 422);
        }

        $user = User::where('phone_number', $request->phone_number)->first();

        if (!$user) {
            return response()->json(['error' => 'Utilisateur non trouvé'], 404);
        }

        if (!$this->verifOtp($user->id, $request->code)) {
            return response()->json(['error' => 'Code OTP invalide'], 401);
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
