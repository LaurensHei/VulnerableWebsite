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

const session = require("express-session");
const crypto = require("crypto");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 15 * 60 * 1000, // Set a more reasonable 15-minute session timeout
      secure: process.env.NODE_ENV === "production", // Secure cookies only in production
      httpOnly: true, // Prevent access via JavaScript (mitigates XSS attacks)
      sameSite: "strict", // Prevent CSRF attacks
    },
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

// Logging utility
function logEvent(event, details) {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] ${event}: ${JSON.stringify(details)}\n`;
  fs.appendFile("security.log", logEntry, (err) => {
    if (err) console.error("Failed to write log:", err);
  });
}

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

const bcrypt = require("bcrypt");

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  getUser(username, (err, user) => {
    if (err || !user) {
      logEvent("LOGIN_FAILED", { username, reason: "Invalid credentials" });
      return res.render("login", { error: "Invalid username or password" });
    }

    // Secure: Compare hashed passwords
      bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) {
        logEvent("LOGIN_FAILED", { username, reason: "Incorrect password" });
        return res.render("login", { error: "Invalid username or password" });
      }

      logEvent("LOGIN_SUCCESS", { username });


      // Set session if login is successful
      req.session.user = { username: user.username, role: user.role };
      return res.redirect("/dashboard");
    });
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
      logEvent("TRANSFER_FAILED", { sender, recipient, amount, reason: "Deduction error" });

      return res.render("transfer", {
        error: "Transfer failed (deduction)",
        message: null,
      });
    }
    let addQuery = `UPDATE accounts SET balance = balance + ${amount} WHERE username = '${recipient}'`;
    db.run(addQuery, function (err) {
      if (err) {
        logEvent("TRANSFER_FAILED", { sender, recipient, amount, reason: "Credit error" });
        return res.render("transfer", {
          error: "Transfer failed (credit)",
          message: null,
        });
      }

      logEvent("TRANSFER_SUCCESS", { sender, recipient, amount });

      res.render("transfer", {
        error: null,
        message: `Transferred ${amount} to ${recipient}`,
      });
    });
  });
});

app.get("/admin", (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    logEvent("ADMIN_ACCESS_DENIED", { username: req.session.user?.username || "unknown" });
    return res.status(403).send("Access denied");
  }

  logEvent("ADMIN_ACCESS", { username: req.session.user.username });


  try {
    const filePath = path.join(__dirname, "users.txt");

    // Prevent reading unintended files
    if (!filePath.startsWith(__dirname)) {
      return res.status(403).send("Access denied");
    }

    const data = fs.readFileSync(filePath, "utf8");

    // Sanitize output to prevent HTML injection
    const sanitizedData = data.replace(/</g, "&lt;").replace(/>/g, "&gt;");

    res.render("admin", { usersData: sanitizedData });
  } catch (err) {
    res.status(500).send("Error loading admin panel");
  }
});


// GET /api/users – Exposed API that returns the raw users file (plaintext credentials)
app.get("/api/users", (req, res) => {
  logEvent("API_USERS_ACCESS", { username: req.session.user?.username || "unknown" });

  fs.readFile("users.txt", "utf8", (err, data) => {
    if (err) {
      return res.status(500).send("Error reading users file");
    }
    res.type("text/plain").send(data);
  });
});

app.get("/search", (req, res) => {
  let username = req.query.username || "";

  let query = "SELECT * FROM accounts WHERE username = ?"; // safe query
  db.all(query, [username], (err, rows) => {
    if (err) {
      return res.status(500).send("Error in query");
    }
    res.json(rows);
  });
});

const { execFile } = require("child_process");

app.get("/exec", (req, res) => {
  let cmd = req.query.cmd;
  if (!cmd) {
    return res.status(400).send("No command provided");
  }

  // Allowlist: Only allow predefined safe commands
  const allowedCommands = {
    "date": ["date"],
    "uptime": ["uptime"],
    "ls": ["ls", "-l"]
  };

  if (!allowedCommands[cmd]) {
    return res.status(403).send("Forbidden command");
  }

  execFile(allowedCommands[cmd][0], allowedCommands[cmd].slice(1), (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send("Command execution failed");
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
