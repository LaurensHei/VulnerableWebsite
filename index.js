// index.js
// WARNING: This code is intentionally vulnerable and insecure.
// For educational purposes only.

const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const { exec } = require("child_process");

const app = express();
const PORT = 3000;

// Middleware setup
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: "insecuresecret", // weak secret key
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60000 }, // short session lifetime for demonstration
  })
);

// Serve static files (CSS, images, etc.)
app.use(express.static(path.join(__dirname, "public")));

// Set view engine to EJS
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Initialize SQLite Database for account balances
const db = new sqlite3.Database("bank.db");

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS accounts (
    username TEXT PRIMARY KEY,
    balance INTEGER
  )`);

  // Read users from users.txt and insert them (if not already present)
  fs.readFile("users.txt", "utf8", (err, data) => {
    if (err) {
      console.error("Error reading users.txt:", err);
      return;
    }
    const lines = data.split("\n");
    lines.forEach((line) => {
      if (line.trim() === "") return;
      const [username, password, balance, role] = line.split(":");
      db.run(
        `INSERT OR IGNORE INTO accounts (username, balance) VALUES (?, ?)`,
        [username, parseInt(balance)],
        (err) => {
          if (err) console.error(err);
        }
      );
    });
  });
});

// Utility: Get user credentials from users.txt
function getUser(username, callback) {
  fs.readFile("users.txt", "utf8", (err, data) => {
    if (err) return callback(err);
    const lines = data.split("\n");
    for (let line of lines) {
      if (line.trim() === "") continue;
      const [user, pass, balance, role] = line.split(":");
      if (user === username) {
        return callback(null, {
          username: user,
          password: pass,
          balance: parseInt(balance),
          role: role,
        });
      }
    }
    return callback(null, null);
  });
}

// ------------------------------
// ROUTES
// ------------------------------

// GET /login – Show the login page.
app.get("/login", (req, res) => {
  if (req.session.user) {
    return res.redirect("/dashboard");
  }
  res.render("login", { error: null });
});

// POST /login – Process login (vulnerable: plaintext comparison)
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  getUser(username, (err, user) => {
    if (err || !user) {
      return res.render("login", { error: "Invalid username or password" });
    }
    // Insecure: Compare plaintext passwords.
    if (user.password === password) {
      req.session.user = { username: user.username, role: user.role };
      // Note: Session is not regenerated upon login (vulnerable to session hijacking)
      return res.redirect("/dashboard");
    } else {
      return res.render("login", { error: "Invalid username or password" });
    }
  });
});

// GET /dashboard – User dashboard (requires login)
app.get("/dashboard", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  // Get account balance from SQLite (this query is safe due to parameter binding)
  db.get(
    `SELECT balance FROM accounts WHERE username = ?`,
    [req.session.user.username],
    (err, row) => {
      let balance = row ? row.balance : 0;
      res.render("dashboard", {
        username: req.session.user.username,
        balance: balance,
        isAdmin: req.session.user.role === "admin",
      });
    }
  );
});

// GET /transfer – Money transfer form (CSRF vulnerable)
app.get("/transfer", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  res.render("transfer", { error: null, message: null });
});

// POST /transfer – Process money transfer (vulnerable to SQL injection)
app.post("/transfer", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  let { recipient, amount } = req.body;
  amount = parseInt(amount);
  if (isNaN(amount) || amount <= 0) {
    return res.render("transfer", { error: "Invalid amount", message: null });
  }
  // VULNERABILITY: Using string concatenation to build SQL queries.
  let deductQuery = `UPDATE accounts SET balance = balance - ${amount} WHERE username = '${req.session.user.username}'`;
  db.run(deductQuery, function (err) {
    if (err) {
      return res.render("transfer", {
        error: "Transfer failed (deduction)",
        message: null,
      });
    }
    let addQuery = `UPDATE accounts SET balance = balance + ${amount} WHERE username = '${recipient}'`;
    db.run(addQuery, function (err) {
      if (err) {
        return res.render("transfer", {
          error: "Transfer failed (credit)",
          message: null,
        });
      }
      res.render("transfer", {
        error: null,
        message: `Transferred ${amount} to ${recipient}`,
      });
    });
  });
});

// GET /admin – Admin control panel (broken access control)
app.get("/admin", (req, res) => {
  // VULNERABILITY: No proper check to restrict access to admin users.
  try {
    const filePath = path.join(__dirname, "users.txt");
    const data = fs.readFileSync(filePath, "utf8");

    // Sanitize output (avoid HTML injection)
    const sanitizedData = data.replace(/</g, "&lt;").replace(/>/g, "&gt;");

    res.render("admin", { usersData: sanitizedData });
  } catch (err) {
    res.render("admin", { usersData: "Error reading users.txt" });
  }
});

// GET /api/users – Exposed API that returns the raw users file (plaintext credentials)
app.get("/api/users", (req, res) => {
  fs.readFile("users.txt", "utf8", (err, data) => {
    if (err) {
      return res.status(500).send("Error reading users file");
    }
    res.type("text/plain").send(data);
  });
});

// GET /search – SQL injection demonstration endpoint
app.get("/search", (req, res) => {
  let username = req.query.username || "";
  // VULNERABILITY: Directly concatenating user input into a SQL query.
  let query = `SELECT * FROM accounts WHERE username = '${username}'`;
  db.all(query, [], (err, rows) => {
    if (err) {
      return res.send("Error in query");
    }
    res.json(rows);
  });
});

// GET /exec – Command injection demonstration endpoint
app.get("/exec", (req, res) => {
  let cmd = req.query.cmd;
  if (!cmd) {
    return res.send("No command provided");
  }
  // VULNERABILITY: Executing user-supplied command without validation.
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      return res.send(`Error: ${stderr}`);
    }
    res.send(`<pre>${stdout}</pre>`);
  });
});

// GET /logout – Log out the user.
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

// Home route: redirect based on login status.
app.get("/", (req, res) => {
  if (req.session.user) {
    res.redirect("/dashboard");
  } else {
    res.redirect("/login");
  }
});

// Start the server.
app.listen(PORT, () => {
  console.log(`Vulnerable Banking App listening on port ${PORT}`);
});
