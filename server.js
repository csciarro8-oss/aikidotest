// INTENTIONALLY VULNERABLE demo for GitHub code scanning. Never deploy.
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const _ = require("lodash");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");

const app = express();
app.use(express.json());

// Hardcoded secret (js/hardcoded-credentials)
const JWT_SECRET = "my-super-secret-key";
const db = mysql.createConnection({ host: "localhost", user: "root", password: "admin123" });

// 1. SQL injection (js/sql-injection)
app.get("/user", (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id, (err, rows) => res.json(rows));
});

// 2. Command injection (js/command-line-injection)
app.get("/lookup", (req, res) => {
  exec("nslookup " + req.query.host, (err, stdout) => res.send(stdout));
});

// 3. Reflected XSS (js/reflected-xss)
app.get("/greet", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

// 4. Path traversal (js/path-injection)
app.get("/file", (req, res) => {
  res.send(fs.readFileSync(path.join(__dirname, "uploads", req.query.name), "utf8"));
});

// 5. Code injection via eval (js/code-injection)
app.post("/calc", (req, res) => {
  res.json({ result: eval(req.body.expression) });
});

// 6. Prototype pollution via old lodash (js/prototype-pollution-utility)
app.post("/settings", (req, res) => {
  const settings = _.merge({}, req.body);
  res.json(settings);
});

// 7. Open redirect (js/server-side-unvalidated-url-redirection)
app.get("/go", (req, res) => res.redirect(req.query.url));

// 8. Insecure randomness for a token (js/insecure-randomness)
app.get("/token", (req, res) => {
  res.json({ token: Math.random().toString(36).slice(2) });
});

// 9. JWT with weak/hardcoded secret and no algorithm restriction
app.get("/verify", (req, res) => {
  res.json(jwt.verify(req.query.token, JWT_SECRET));
});

// 10. Inefficient regex / ReDoS (js/polynomial-redos)
app.get("/validate", (req, res) => {
  res.json({ ok: /^(a+)+$/.test(req.query.input || "") });
});

// 11. TLS verification disabled (js/disabling-certificate-validation)
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

app.listen(3000);
