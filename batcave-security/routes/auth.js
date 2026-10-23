// Routeur principal d'authentification de la Batcave (architecture modulaire)
const express = require("express");
const loginRouter = require("./auth/login");
const twoFactorRouter = require("./auth/twoFactor");
const tokensRouter = require("./auth/tokens");
const passwordRouter = require("./auth/password");
const { getUserScopes, auditLog } = require("./auth/helpers");

const router = express.Router();

// Montage des sous-modules spécialisés
router.use(loginRouter);
router.use(twoFactorRouter);
router.use(tokensRouter);
router.use(passwordRouter);

// Exportation des helpers de sécurité
router.getUserScopes = getUserScopes;
router.auditLog = auditLog;

module.exports = router;
