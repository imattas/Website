/**
 * Prototype Pollution Challenge
 * Port: 5011
 *
 * An Express app with a vulnerable deep merge function.
 * Pollute Object.prototype to set isAdmin = true and access /admin.
 */

const express = require("express");
const app = express();
const fs = require("fs");
const path = require("path");

const FLAG = fs
  .readFileSync(path.join(__dirname, "flag.txt"), "utf8")
  .trim();

app.use(express.json());

// VULNERABLE: recursive merge without __proto__ / constructor check
function deepMerge(target, source) {
  for (const key in source) {
    if (
      typeof source[key] === "object" &&
      source[key] !== null &&
      !Array.isArray(source[key])
    ) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

const users = {
  guest: { username: "guest", role: "viewer" },
};

app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Config API</title></head>
    <body>
    <h1>User Config API</h1>
    <p>Endpoints:</p>
    <ul>
      <li><code>POST /api/update</code> — merge JSON into your user config</li>
      <li><code>GET /api/profile</code> — view your profile</li>
      <li><code>GET /admin</code> — admin panel (requires isAdmin)</li>
    </ul>
    <h3>Example:</h3>
    <pre>
curl -X POST http://localhost:5011/api/update \\
  -H "Content-Type: application/json" \\
  -d '{"theme": "dark"}'
    </pre>
    </body>
    </html>
  `);
});

app.post("/api/update", (req, res) => {
  const userData = users["guest"];
  // VULNERABLE: deep merge with user-controlled JSON
  deepMerge(userData, req.body);
  res.json({ message: "Config updated", user: userData });
});

app.get("/api/profile", (req, res) => {
  const user = users["guest"];
  res.json(user);
});

app.get("/admin", (req, res) => {
  const user = users["guest"];
  // Check isAdmin — can be set via prototype pollution
  if (user.isAdmin) {
    res.send(`<h1>Admin Panel</h1><p>Flag: ${FLAG}</p>`);
  } else {
    res.status(403).json({ error: "Access denied. isAdmin is not set." });
  }
});

app.listen(5011, "0.0.0.0", () => {
  console.log("[*] Prototype Pollution challenge running on port 5011");
});
