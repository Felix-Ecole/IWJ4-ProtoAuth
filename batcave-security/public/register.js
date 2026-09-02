// Récupération des éléments clés du DOM
const form = document.getElementById("registerForm");
const alertBox = document.getElementById("alertBox");

// Fonction utilitaire pour afficher les messages de retour utilisateur
function showAlert(message, isSuccess = false) {
	// Application dynamique du style visuel selon le succès ou l'échec
	alertBox.className = `p-3 rounded-lg text-sm font-medium ${
		isSuccess
			? "bg-emerald-950/80 text-emerald-300 border border-emerald-800"
			: "bg-red-950/80 text-red-300 border border-red-800"
	}`;
	alertBox.textContent = message;
	alertBox.classList.remove("hidden");
}

// Gestion de la soumission du formulaire d'inscription
form.addEventListener("submit", async (e) => {
	// Empêche le rechargement standard de la page
	e.preventDefault();

	// Extraction et nettoyage des valeurs saisies
	const username = document.getElementById("username").value.trim();
	const password = document.getElementById("password").value;

	// Vérification préalable de la longueur du mot de passe côté client
	if (password.length < 8) {
		showAlert("Le mot de passe doit comporter au moins 8 caractères.");
		return;
	}

	try {
		// Envoi de la requête d'inscription au serveur Express
		const res = await fetch("/register", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username, password }),
		});

		// Lecture du corps de la réponse JSON
		const data = await res.json();

		// Si le serveur renvoie une erreur (400, 409, 500)
		if (!res.ok) {
			showAlert(data.error || "Une erreur est survenue lors de l'enregistrement.");
			return;
		}

		// Inscription validée avec succès
		showAlert(data.message || "Justicier enregistré avec succès !", true);
		form.reset();
	} catch (err) {
		// Gestion de l'échec réseau ou indisponibilité serveur
		console.error("Erreur réseau :", err);
		showAlert("Impossible de contacter le serveur de la Batcave.");
	}
});
