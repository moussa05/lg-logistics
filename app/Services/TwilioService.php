<?php

namespace App\Services;

use Twilio\Rest\Client;

class TwilioService
{
    public static function sendOtp($to, $otp)
    {
        $client = new Client(
            env('TWILIO_SID'),
            env('TWILIO_TOKEN')
        );

        return $client->messages->create(
            $to,
            [
                'from' => env('TWILIO_FROM'),
                'body' => "LG LOGISTICS\nVotre code OTP est : {$otp}.\nValable 5 minutes."
            ]
        );
    }
}