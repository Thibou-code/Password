#!/bin/bash

API_URL="http://localhost:8888/api/passwords"

echo "--- 🚀 Démarrage des tests de l'API Password Manager ---"

# 1. Tester la génération (POST)
echo -e "\n[1] Test de génération de mot de passe..."
curl -s -X POST "$API_URL/generate" \
     -H "Content-Type: application/json" \
     -d '{"site": "Github"}' | grep -q "ok" && echo "✅ Succès" || echo "❌ Échec"

# 2. Tester la liste (GET)
echo -e "\n[2] Test de récupération de la liste..."
LIST=$(curl -s -X GET "$API_URL")
if [[ $LIST == *"Github"* ]]; then
    echo "✅ Succès : 'Github' trouvé dans la liste"
else
    echo "❌ Échec : Données non trouvées"
fi

# 3. Tester le filtrage (GET avec argument)
echo -e "\n[3] Test du filtrage (?site=Github)..."
FILTER=$(curl -s -X GET "$API_URL?site=Github")
if [[ $FILTER == *"Github"* ]]; then
    echo "✅ Succès"
else
    echo "❌ Échec du filtrage"
fi

# 4. Tester la suppression (DELETE / POST delete)
# Note : On récupère d'abord l'ID de l'entrée "Github" via un petit hack grep/sed
ID=$(echo $LIST | grep -oE '"id":[0-9]+' | head -1 | cut -d: -f2)

echo -e "\n[4] Test de suppression de l'ID $ID..."
curl -s -X DELETE "$API_URL/delete?id=$ID"
echo "✅ Requête envoyée (vérifiez manuellement la liste)"

echo -e "\n--- 🏁 Fin des tests ---"