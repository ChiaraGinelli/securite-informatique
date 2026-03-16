const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).json({ error: "Accès refusé : token manquant" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Accès refusé : token manquant" });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
    if (err) {
      return res
        .status(403)
        .json({ error: "Token expiré ou fausse signature" });
    }
    req.user = decodedUser;
    next();
  });
};

module.exports = verifyToken;
