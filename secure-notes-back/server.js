require("dotenv").config();
const jwt = require("jsonwebtoken");
const express = require("express");
const cors = require("cors");
const sanitizeHtml = require("sanitize-html");
const { body, validationResult, param } = require("express-validator");
const helmet = require("helmet");
const fs = require("fs");
const authMiddleware = require("./middleware/auth");
const isAdmin = require("./middleware/isAdmin");
const db = require("./database");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");

const app = express();
const saltRounds = 10;
const LOCK_TIME = 15 * 60 * 1000;

app.use(helmet());
app.use(express.json());

app.use(
  cors({
    origin: "http://localhost:5173",
    methods: ["GET", "POST", "PUT", "DELETE"],
  }),
);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error:
        "Trop de tentatives de connexion. Veuillez patienter 15 minutes avant de réessayer.",
    });
  },
});

const adminDeleteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error:
      "Trop de suppressions effectuées. Veuillez patienter 15 minutes avant de réessayer.",
  },
});

const hashPassword = async (plainPassword) => {
  try {
    return await bcrypt.hash(plainPassword, saltRounds);
  } catch (error) {
    console.error("Erreur lors du hachage du mot de passe :", error);
    throw error;
  }
};

const verifyPassword = async (plainPassword, hashedPassword) => {
  try {
    return await bcrypt.compare(plainPassword, hashedPassword);
  } catch (error) {
    console.error("Erreur lors de la vérification du mot de passe :", error);
    throw error;
  }
};

const generateToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: "24h" },
  );
};

const logSecurityEvent = (message) => {
  const timestamp = new Date().toISOString();
  const log = `[${timestamp}] ${message}\n`;

  fs.appendFile("security.log", log, (err) => {
    if (err) {
      console.error("Erreur écriture log :", err);
    }
  });
};

const logAdminAction = (adminId, deletedUserId) => {
  const timestamp = new Date().toISOString();
  const log = `[${timestamp}] - L'admin ${adminId} a supprimé l'utilisateur ${deletedUserId}\n`;

  fs.appendFile("admin_actions.log", log, (err) => {
    if (err) {
      console.error("Erreur écriture admin_actions.log :", err);
    }
  });
};

app.post("/api/auth/signup", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email et mot de passe requis" });
  }

  const checkQuery = "SELECT * FROM users WHERE email = ?";

  db.get(checkQuery, [email], async (err, existingUser) => {
    if (err) {
      console.error("Erreur vérification email :", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }

    if (existingUser) {
      return res.status(409).json({ error: "Email déjà utilisé" });
    }

    try {
      const hashedPassword = await hashPassword(password);

      const insertQuery = `
        INSERT INTO users (email, password, role, failed_attempts)
        VALUES (?, ?, ?, ?)
      `;

      db.run(insertQuery, [email, hashedPassword, "user", 0], function (err) {
        if (err) {
          console.error("Erreur inscription :", err);
          return res.status(500).json({ error: "Erreur serveur" });
        }

        const user = {
          id: this.lastID,
          email,
          role: "user",
          failed_attempts: 0,
        };

        const token = generateToken(user);

        res.status(201).json({
          user,
          token,
        });
      });
    } catch (error) {
      console.error("Erreur hachage inscription :", error);
      res.status(500).json({ error: "Erreur lors du hachage du mot de passe" });
    }
  });
});

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email et mot de passe requis" });
  }

  const query = "SELECT * FROM users WHERE email = ?";

  db.get(query, [email], async (err, user) => {
    if (err) {
      console.error("Erreur login :", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }

    if (!user) {
      return res.status(401).json({ error: "Identifiants incorrects" });
    }

    const now = Date.now();
    const failedAttempts = Number(user.failed_attempts) || 0;
    const lockUntil = user.lock_until ? Number(user.lock_until) : null;

    if (lockUntil && now < lockUntil) {
      logSecurityEvent(
        `Compte verrouillé : tentative refusée pour ${user.email}`,
      );

      return res.status(403).json({
        error: "Compte temporairement bloqué",
      });
    }

    try {
      const match = await verifyPassword(password, user.password);

      if (!match) {
        const newAttempts = failedAttempts + 1;

        if (newAttempts >= 3) {
          const newLockUntil = now + LOCK_TIME;

          db.run(
            `
            UPDATE users
            SET failed_attempts = ?, lock_until = ?
            WHERE id = ?
            `,
            [newAttempts, newLockUntil, user.id],
            function (updateErr) {
              if (updateErr) {
                console.error("Erreur compte bloqué :", updateErr);
                return res.status(500).json({ error: "Erreur serveur" });
              }
              logSecurityEvent(
                `Compte bloqué pendant 15 minutes pour ${user.email}`,
              );

              return res.status(403).json({
                error: "Compte bloqué pendant 15 minutes",
              });
            },
          );

          return;
        }

        db.run(
          `
          UPDATE users
          SET failed_attempts = ?
          WHERE id = ?
          `,
          [newAttempts, user.id],
          function (updateErr) {
            if (updateErr) {
              console.error("Erreur incrément failed_attempts :", updateErr);
              return res.status(500).json({ error: "Erreur serveur" });
            }

            return res.status(401).json({ error: "Identifiants incorrects" });
          },
        );

        return;
      }

      db.run(
        `
        UPDATE users
        SET failed_attempts = 0, lock_until = NULL
        WHERE id = ?
        `,
        [user.id],
        function (updateErr) {
          if (updateErr) {
            console.error("Erreur reset sécurité :", updateErr);
            return res.status(500).json({ error: "Erreur serveur" });
          }

          const safeUser = {
            id: user.id,
            email: user.email,
            role: user.role,
            failed_attempts: 0,
            lock_until: null,
          };

          const token = generateToken(safeUser);

          res.json({
            user: safeUser,
            token,
          });
        },
      );
    } catch (error) {
      console.error("Erreur vérification mot de passe :", error);
      return res.status(500).json({
        error: "Erreur lors de la vérification du mot de passe",
      });
    }
  });
});

app.get("/api/notes", authMiddleware, (req, res) => {
  const userId = req.user.id;
  const query = "SELECT * FROM notes WHERE user_id = ?";

  db.all(query, [userId], (err, notes) => {
    if (err) {
      console.error("Erreur récupération notes :", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }

    res.json(notes);
  });
});

app.post("/api/notes", authMiddleware, (req, res) => {
  const { content } = req.body;
  const userId = req.user.id;

  if (!content) {
    return res.status(400).json({ error: "Le contenu de la note est requis" });
  }

  const cleanContent = sanitizeHtml(content, {
    allowedTags: [],
    allowedAttributes: {},
  });

  const query = "INSERT INTO notes (content, user_id) VALUES (?, ?)";

  db.run(query, [cleanContent, userId], function (err) {
    if (err) {
      console.error("Erreur ajout note :", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }

    res.status(201).json({
      id: this.lastID,
      content: cleanContent,
      user_id: userId,
    });
  });
});

app.delete("/api/notes/:id", authMiddleware, (req, res) => {
  const noteId = req.params.id;
  const userId = req.user.id;

  const query = "DELETE FROM notes WHERE id = ? AND user_id = ?";

  db.run(query, [noteId, userId], function (err) {
    if (err) {
      console.error("Erreur suppression note :", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }

    if (this.changes === 0) {
      return res.status(403).json({
        error: "Accès refusé : note introuvable ou non autorisée",
      });
    }

    res.json({ message: "Note supprimée avec succès" });
  });
});

// Mission 2 : Le Verrouillage du Back-Office
app.get("/api/admin/users", authMiddleware, isAdmin, (req, res) => {
  const query = "SELECT id, email, role, bio FROM users";

  db.all(query, [], (err, users) => {
    if (err) {
      console.error("Erreur récupération utilisateurs admin :", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }

    return res.json(users);
  });
});

app.post("/api/auth/change-password", async (req, res) => {
  const { email, oldPassword, newPassword } = req.body;

  if (!email || !oldPassword || !newPassword) {
    return res.status(400).json({ error: "Champs requis manquants" });
  }

  const query = "SELECT * FROM users WHERE email = ?";

  db.get(query, [email], async (err, user) => {
    if (err) {
      console.error("Erreur change-password :", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }

    if (!user) {
      return res.status(404).json({ error: "Utilisateur non trouvé" });
    }

    try {
      const match = await verifyPassword(oldPassword, user.password);

      if (!match) {
        return res.status(401).json({ error: "Ancien mot de passe incorrect" });
      }

      const newHashedPassword = await hashPassword(newPassword);
      const updateQuery = "UPDATE users SET password = ? WHERE email = ?";

      db.run(updateQuery, [newHashedPassword, email], function (err) {
        if (err) {
          console.error("Erreur update mot de passe :", err);
          return res.status(500).json({ error: "Erreur serveur" });
        }

        res.json({ message: "Mot de passe mis à jour avec succès" });
      });
    } catch (error) {
      console.error("Erreur changement mot de passe :", error);
      res
        .status(500)
        .json({ error: "Erreur lors du changement de mot de passe" });
    }
  });
});

// Mission 1 : L'Édition de Profil
app.put(
  "/api/users/:id",
  authMiddleware,
  [
    param("id").isInt({ min: 1 }).withMessage("ID utilisateur invalide"),
    body("email").isEmail().withMessage("Format d'email invalide"),
    body("bio").optional().isString().withMessage("La bio doit être un texte"),
  ],
  (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
      });
    }

    const userIdFromToken = Number(req.user.id);
    const userIdFromParams = Number(req.params.id);
    const { email, bio = "" } = req.body;

    if (userIdFromToken !== userIdFromParams) {
      return res.status(403).json({
        error: "Accès refusé : vous ne pouvez modifier que votre propre profil",
      });
    }

    const cleanBio = sanitizeHtml(bio, {
      allowedTags: ["b", "i", "em", "strong", "p", "br", "ul", "ol", "li"],
      allowedAttributes: {
        a: [],
      },
      allowedSchemes: [],
    });

    const updateQuery = `
      UPDATE users
      SET email = ?, bio = ?
      WHERE id = ?
    `;

    db.run(updateQuery, [email, cleanBio, userIdFromParams], function (err) {
      if (err) {
        console.error("Erreur mise à jour profil :", err);

        if (err.message && err.message.includes("UNIQUE")) {
          return res.status(409).json({
            error: "Cet email est déjà utilisé",
          });
        }

        return res.status(500).json({
          error: "Erreur serveur",
        });
      }

      if (this.changes === 0) {
        return res.status(404).json({
          error: "Utilisateur introuvable",
        });
      }

      return res.json({
        message: "Profil mis à jour avec succès",
        user: {
          id: userIdFromParams,
          email,
          bio: cleanBio,
        },
      });
    });
  },
);

// Mission 3 : La Modération Extrême
app.delete(
  "/api/admin/users/:id",
  authMiddleware,
  isAdmin,
  adminDeleteLimiter,
  (req, res) => {
    const adminId = req.user.id;
    const userIdToDelete = Number(req.params.id);

    if (!Number.isInteger(userIdToDelete) || userIdToDelete <= 0) {
      return res.status(400).json({ error: "ID utilisateur invalide" });
    }

    if (adminId === userIdToDelete) {
      return res.status(403).json({
        error: "Un administrateur ne peut pas supprimer son propre compte",
      });
    }

    const checkUserQuery = "SELECT id, role FROM users WHERE id = ?";

    db.get(checkUserQuery, [userIdToDelete], (checkErr, user) => {
      if (checkErr) {
        console.error(
          "Erreur vérification utilisateur à supprimer :",
          checkErr,
        );
        return res.status(500).json({ error: "Erreur serveur" });
      }

      if (!user) {
        return res.status(404).json({ error: "Utilisateur introuvable" });
      }

      db.run(
        "DELETE FROM notes WHERE user_id = ?",
        [userIdToDelete],
        function (notesErr) {
          if (notesErr) {
            console.error("Erreur suppression notes utilisateur :", notesErr);
            return res.status(500).json({ error: "Erreur serveur" });
          }

          db.run(
            "DELETE FROM users WHERE id = ?",
            [userIdToDelete],
            function (userErr) {
              if (userErr) {
                console.error("Erreur suppression utilisateur :", userErr);
                return res.status(500).json({ error: "Erreur serveur" });
              }

              if (this.changes === 0) {
                return res
                  .status(404)
                  .json({ error: "Utilisateur introuvable" });
              }

              logAdminAction(adminId, userIdToDelete);

              return res.json({
                message: "Utilisateur et notes associées supprimés avec succès",
              });
            },
          );
        },
      );
    });
  },
);

// Mission 5 : L'Audit en temps réel
app.get("/api/admin/logs", authMiddleware, isAdmin, (req, res) => {
  fs.readFile("admin_actions.log", "utf8", (err, data) => {
    if (err) {
      if (err.code === "ENOENT") {
        return res.json({ logs: [] });
      }

      console.error("Erreur lecture admin_actions.log :", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }

    const logs = data
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line !== "");

    return res.json({ logs });
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Serveur Back-end démarré sur http://localhost:${PORT}`);
});
