const fs = require("fs");

const logSecurityEvent = (message) => {
  const timestamp = new Date().toISOString();
  const log = `[${timestamp}] ${message}\n`;

  fs.appendFile("security.log", log, (err) => {
    if (err) {
      console.error("Erreur écriture log :", err);
    }
  });
};

module.exports = (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    return next();
  }

  logSecurityEvent(
    `Tentative d'accès admin refusée pour user ${req.user?.email || "inconnu"}`
  );

  return res.status(403).json({
    error: "Accès refusé : administrateur uniquement",
  });
};