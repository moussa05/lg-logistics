<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Formulaire d'enregistrement</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        form#multiStepForm {
            padding: 7vh 3vw;
        }
        .form-step {
            position: relative;
            width: 100%;
        }

        .form-group {
            position: relative;
            width: 100%;
        }

        form {
            background-color: #fff;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            max-width: 100%;
        }

        h2 {
            text-align: center;
            margin-bottom: 20px;
        }

        .form-step {
            display: none;
        }

        .form-step-active {
            display: block;
        }

        .form-group {
            margin-bottom: 15px;
        }

        .form-group label {
            display: block;
            margin-bottom: 5px;
        }

        .form-group input,
        .form-group textarea {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }

        .form-group .image-previews {
            display: flex;
            flex-wrap: wrap;
            margin-top: 10px;
        }

        .form-group .image-previews .image-wrapper {
            position: relative;
            display: inline-block;
            margin-right: 10px;
            margin-top: 5px;
        }

        .form-group .image-previews img {
            width: 50px;
            height: 50px;
            object-fit: cover;
        }

        .form-group .image-previews .remove-btn {
            position: absolute;
            top: -5px;
            right: -5px;
            background-color: red;
            color: white;
            border: none;
            border-radius: 50%;
            width: 18px;
            height: 18px;
            text-align: center;
            font-size: 12px;
            cursor: pointer;
        }

        .btn {
            display: inline-block;
            padding: 10px 15px;
            background-color: #007bff;
            color: white;
            text-align: center;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }

        .btn[disabled] {
            background-color: #ddd;
        }

        .btn-group {
            display: flex;
            justify-content: space-between;
            margin-top: 20px;
        }
        img.logo {
            height: auto;
            width: 150px;
            margin: 0 auto;
            position: relative;
            left: 50%;
            transform: translate(-50%);
            margin-bottom: 2em;
        }

        h2 {
            margin-top: 0;
            margin-bottom: 2em;
            /* color: #013e98; */
            text-transform: uppercase;
        }
        p.sub {
            font-size: 15px;
            font-weight: 500;
            text-transform: none;
        }

    </style>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.5/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-SgOJa3DmI69IUzQ2PVdRZhwQ+dy64/BUtbMJw1MZ8t5HZApcHrRKUc4W0kG879m7" crossorigin="anonymous">
</head>
<body>
    <form id="multiStepForm">
        <img class="logo" src="{{ asset('storage/images/lglogo.png') }}" alt="" srcset="">
        <h2>
            Enregistrement Chauffeur
            <p class="sub">Veuillez remplir ce formulaire ci-dessous</p>
        </h2>

        <!-- Étape 1 : Informations personnelles -->
        <div class="form-step form-step-active">
            <div class="form-group">
                <label class="form-label" for="prenom">Prénom :</label>
                <input class="form-control" type="text" id="prenom" name="prenom" required>
            </div>

            <div class="form-group">
                <label class="form-label" for="nom">Nom :</label>
                <input class="form-control" type="text" id="nom" name="nom" required>
            </div>

            <div class="form-group">
                <label class="form-label" for="date_naissance">Date de naissance :</label>
                <input class="form-control" type="date" id="date_naissance" name="date_naissance" required>
            </div>

            <div class="form-group">
                <label class="form-label" for="telephone">Numéro de téléphone :</label>
                <input class="form-control" type="tel" id="telephone" name="telephone" required>
            </div>

            <div class="btn-group">
                <button type="button" class="btn btn-primary" id="next1">Suivant</button>
            </div>
        </div>

        <!-- Étape 2 : Informations véhicule -->
        <div class="form-step">
            <div class="form-group">
                <label class="form-label" for="marque">Marque du véhicule :</label>
                <input class="form-control" type="text" id="marque" name="marque" required>
            </div>

            <div class="form-group">
                <label class="form-label" for="modele">Modèle du véhicule :</label>
                <input class="form-control" type="text" id="modele" name="modele" required>
            </div>

            <div class="form-group">
                <label class="form-label" for="photo_vehicule">Image(s) descriptive(s) du véhicule :</label>
                <input class="form-control" type="file" id="photo_vehicule" name="photo_vehicule[]" accept="image/*" multiple onchange="previewImages('photo_vehicule', 'vehicule-previews')">
                <div class="image-previews" id="vehicule-previews"></div>
            </div>

            <div class="form-group">
                <label class="form-label" for="carte_grise">Photo(s) de la carte grise :</label>
                <input class="form-control" type="file" id="carte_grise" name="carte_grise[]" accept="image/*" multiple onchange="previewImages('carte_grise', 'carte-grise-previews')">
                <div class="image-previews" id="carte-grise-previews"></div>
            </div>

            <div class="form-group">
                <label class="form-label" for="assurance">Photo(s) de l'assurance :</label>
                <input class="form-control" type="file" id="assurance" name="assurance[]" accept="image/*" multiple onchange="previewImages('assurance', 'assurance-previews')">
                <div class="image-previews" id="assurance-previews"></div>
            </div>

            <div class="btn-group">
                <button type="button" class="btn btn-primary" id="prev2">Précédent</button>
                <button type="button" class="btn btn-primary" id="next2">Suivant</button>
            </div>
        </div>

        <!-- Étape 3 : Informations chauffeur -->
        <div class="form-step">
            <div class="form-group">
                <label class="form-label" for="permis_conduire">Photo(s) du permis de conduire :</label>
                <input class="form-control" type="file" id="permis_conduire" name="permis_conduire[]" accept="image/*" multiple onchange="previewImages('permis_conduire', 'permis-previews')">
                <div class="image-previews" id="permis-previews"></div>
            </div>

            <div class="form-group">
                <label class="form-label" for="experience_vtc">Avez-vous déjà fait du VTC ?</label>
                <input class="form-control" type="checkbox" id="experience_vtc" name="experience_vtc">
            </div>

            <div class="form-group">
                <label class="form-label" for="disponibilite">Horaires de disponibilité :</label>
                <input class="form-control" type="text" id="disponibilite" name="disponibilite" placeholder="Ex : 9h-18h" required>
            </div>

            <div class="form-group">
                <label class="form-label" for="message_motivation">Message de motivation (optionnel) :</label>
                <textarea id="message_motivation" name="message_motivation" rows="4"></textarea>
            </div>

            <div class="btn-group">
                <button type="button" class="btn btn-primary" id="prev3">Précédent</button>
                <button type="submit" class="btn btn-primary">Envoyer</button>
            </div>
        </div>
    </form>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.5/dist/js/bootstrap.bundle.min.js" integrity="sha384-k6d4wzSIapyDyv1kpU366/PK5hCdSbCRGRCMv+eplOQJWyd1fbcAu9OCUj5zNLiq" crossorigin="anonymous"></script>
    <script>
        const next1 = document.getElementById('next1');
        const next2 = document.getElementById('next2');
        const prev2 = document.getElementById('prev2');
        const prev3 = document.getElementById('prev3');

        const steps = document.querySelectorAll('.form-step');

        let currentStep = 0;

        function showStep(step) {
            steps.forEach((formStep, index) => {
                formStep.classList.toggle('form-step-active', index === step);
            });
        }

        next1.addEventListener('click', () => {
            currentStep++;
            showStep(currentStep);
        });

        next2.addEventListener('click', () => {
            currentStep++;
            showStep(currentStep);
        });

        prev2.addEventListener('click', () => {
            currentStep--;
            showStep(currentStep);
        });

        prev3.addEventListener('click', () => {
            currentStep--;
            showStep(currentStep);
        });

        function previewImages(inputId, previewContainerId) {
            const input = document.getElementById(inputId);
            const previewContainer = document.getElementById(previewContainerId);
            previewContainer.innerHTML = ''; // Clear previous previews

            const files = input.files;
            for (let i = 0; i < files.length; i++) {
                const file = files[i];
                const reader = new FileReader();

                reader.onload = function (e) {
                    const imageWrapper = document.createElement('div');
                    imageWrapper.classList.add('image-wrapper');

                    const img = document.createElement('img');
                    img.src = e.target.result;

                    const removeBtn = document.createElement('button');
                    removeBtn.classList.add('remove-btn');
                    removeBtn.innerHTML = '×';

                    // Event listener to remove the image preview and file from input
                    removeBtn.addEventListener('click', function () {
                        imageWrapper.remove();
                        removeFile(input, file);
                    });

                    imageWrapper.appendChild(img);
                    imageWrapper.appendChild(removeBtn);
                    previewContainer.appendChild(imageWrapper);
                };

                reader.readAsDataURL(file);
            }
        }

        function removeFile(input, fileToRemove) {
            const dataTransfer = new DataTransfer();
            const files = input.files;

            for (let i = 0; i < files.length; i++) {
                if (files[i] !== fileToRemove) {
                    dataTransfer.items.add(files[i]);
                }
            }

            input.files = dataTransfer.files; // Update the input files list
        }
    </script>
</body>
</html>
