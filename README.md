TD-Ransomware - Cybersécurité
Question 1

Quel est le nom de l'algorithme utilisé pour le cryptage des fichiers dans le ransomware TD ?

    L'algorithme utilisé est le cryptage XOR.
    Cependant, la clé peut être retrouvée en possédant un fichier à la fois en clair et encrypté.

Question 2

Pourquoi la clé est-elle envoyée au serveur CNC et pourquoi utilise-t-on HMAC ?

    La clé est envoyée au serveur CNC pour être utilisée plus tard pour déchiffrer les fichiers.
    HMAC est utilisé pour vérifier l'intégrité des données.

Question 3

Quels sont les deux principales raisons pour éviter d'écrire dans un fichier contenant déjà quelque chose ?

    Pour éviter de perdre le token.
    Pour éviter de compromettre une victime déjà infectée.

Question 4

Comment vérifie-t-on que la clé envoyée au serveur CNC est la bonne ?

    On demande au serveur CNC de vérifier la clé.

Bonus 1

Quel est le processus lorsqu'un client infecté envoie une requête POST au serveur CNC ?

    Le client envoie une requête POST avec tous les fichiers à chiffrer.
    Une fois reçus, les fichiers sont stockés dans le dossier correspondant au token.

Bonus 2

Comment retrouve-t-on la clé utilisée pour crypter les fichiers ?

    On effectue une opération XOR sur un fichier clair et le même fichier crypté pour obtenir la clé répétée autant de fois qu'il est nécessaire pour atteindre la taille du fichier.
    Voir sources/chiffrement_answer.py.

Bonus 3

Qu'est-ce que Fernet et pourquoi l'utilise-t-on ?

    Fernet est un module Python qui permet de crypter et décrypter des données.
    On l'utilise pour garantir que le message crypté ne peut être lu ou manipulé sans la clé.

Bonus 4

Quelle commande permet de créer un exécutable à partir du code Python source ?

    La commande est : pyinstaller --onefile --windowed source/ransomware.py.

Bonus 5

Où est-ce que l'exécutable créé par la commande mentionnée dans le bonus 4 est enregistré ?

    L'exécutable est enregistré dans le dossier "dist".