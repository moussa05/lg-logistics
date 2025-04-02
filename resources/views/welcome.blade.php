<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>LG LOGISTICS - Devenir chauffeur</title>
    @vite(['resources/sass/app.scss', 'resources/js/app.js'])
</head>
<body>
    <main class="home-screen">
        <div class="starter">
            <div class="starter-left"></div>
            <div class="starter-right">
                <hr class="before">
                <h1>Rejoignez l'aventure !</h1>
                <p>
                    Rejoignez dès aujourd'hui LG LOGISTICS, la nouvelle application VTC qui valorise votre profession ! Inscrivez-vous rapidement et commencez à recevoir des courses en toute simplicité. Profitez d’une plateforme innovante qui vous garantit flexibilité, sécurité et de nombreux clients à portée de main. Faites le bon choix pour booster votre activité. Let's Go !
                </p>
                <a href="{{ route('chauffeurs.create') }}" class="buttonstarter"><span class="text-btn">S'inscrire </span><span class="icon-btn"><i class="fa-solid fa-chevron-right"></i></span></a>
            </div>
        </div>
    </main>
</body>
</html>