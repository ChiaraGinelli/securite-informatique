require("dotenv").config();
const jwt = require("jsonwebtoken");
const express = require("express");
const cors = require("cors");
const authMiddleware = require('./middleware/auth');
const app = express();
const db = require("./database");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const hashPassword = async (plainPassword) => {
  try {
    //const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
    return hashedPassword;
  } catch (error) {
    console.error("Erreur lors du hachage du mot de passe :", error);
    throw error;
  }
};

const verifyPassword = async (plainPassword, hashedPassword) => {
  try {
    const match = await bcrypt.compare(plainPassword, hashedPassword);
    if (match) {
      console.log("✅ Mot de passe valide");
    } else {
      console.log("❌ Mot de passe invalide");
    }
    return match;
  } catch (error) {
    console.error("Erreur lors de la vérification du mot de passe :", error);
    throw error;
  }
};

const generateToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: "24h",
  });
};

app.use(cors());
app.use(express.json());

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const query = "SELECT * FROM users WHERE email = ?";

  db.get(query, [email], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: "Erreur serveur" });
    }
    if (!user)
      return res.status(401).json({ error: "Identifiants incorrects" });

    try {
      const match = await verifyPassword(password, user.password);
      if (match) {
        const token = generateToken(user);

        delete user.password;

        res.json({
          user,
          token,
        });
      } else {
        res.status(401).json({ error: "Identifiants incorrects" });
      }
    } catch (error) {
      res
        .status(500)
        .json({ error: "Erreur lors de la vérification du mot de passe" });
    }
  });
});

app.post("/api/auth/signup", async (req, res) => {
  const { email, password } = req.body;

  const checkQuery = "SELECT * FROM users WHERE email = ?";
  db.get(checkQuery, [email], async (err, existingUser) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    if (existingUser)
      return res.status(409).json({ error: "Email déjà utilisé" });

    try {
      const hashedPassword = await hashPassword(password);
      const insertQuery = "INSERT INTO users (email, password) VALUES (?, ?)";
      db.run(insertQuery, [email, hashedPassword], function (err) {
        if (err) return res.status(500).json({ error: "Erreur serveur" });

        const user = { id: this.lastID, email };

        const token = generateToken(user);

        res.json({
          user,
          token,
        });
      });
    } catch (error) {
      res.status(500).json({ error: "Erreur lors du hachage du mot de passe" });
    }
  });
});

app.get("/api/notes", authMiddleware, (req, res) => {
  res.json({
    message: "Accès autorisé aux notes",
    userId: req.user.id,
    email: req.user.email
  });
});

app.post("/api/auth/change-password", async (req, res) => {
  const { email, oldPassword, newPassword } = req.body;

  const query = "SELECT * FROM users WHERE email = ?";

  db.get(query, [email], async (err, user) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });

    if (!user) return res.status(404).json({ error: "Utilisateur non trouvé" });

    try {
      const match = await verifyPassword(oldPassword, user.password);

      if (!match) {
        return res.status(401).json({ error: "Ancien mot de passe incorrect" });
      }

      const newHashedPassword = await hashPassword(newPassword);

      const updateQuery = "UPDATE users SET password = ? WHERE email = ?";

      db.run(updateQuery, [newHashedPassword, email], function (err) {
        if (err) return res.status(500).json({ error: "Erreur serveur" });

        res.json({ message: "Mot de passe mis à jour avec succès" });
      });
    } catch (error) {
      res
        .status(500)
        .json({ error: "Erreur lors du changement de mot de passe" });
    }
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`
🚀
 Serveur Back-end démarré sur http://localhost:${PORT}`);
});
