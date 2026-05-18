const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const child_process = require('child_process');
const mysql = require('mysql2');

const app = express();
app.use(express.json());

const db = mysql.createConnection({ host: 'localhost', user: 'root', password: 'root', database: 'test' });

const hardcodedPassword = "admin123";
const apiKey = "sk_test_1234567890abcdef";

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  next();
});

app.get('/normal-command', (req, res) => {
  const cmd = req.query.cmd;
  child_process.exec(cmd);
  res.send('done');
});

app.get('/normal-eval', (req, res) => {
  const code = req.query.code;
  eval(code);
  res.send('done');
});

app.get('/normal-sql', (req, res) => {
  const name = req.query.name;
  const sql = "SELECT * FROM users WHERE name = '" + name + "'";
  db.query(sql, (err, rows) => res.json(rows));
});

app.get('/normal-crypto', (req, res) => {
  const h1 = crypto.createHash('md5').update(req.query.value || 'x').digest('hex');
  const h2 = crypto.createHash('sha1').update(req.query.value || 'x').digest('hex');
  res.send(h1 + h2);
});

app.get('/normal-random', (req, res) => {
  const token = Math.random().toString(36);
  res.send(token);
});

app.get('/normal-path', (req, res) => {
  const file = req.query.file;
  const data = fs.readFileSync('./uploads/' + file, 'utf8');
  res.send(data);
});

app.get('/normal-jwt', (req, res) => {
  const token = req.headers.authorization;
  const decoded = jwt.decode(token);
  res.json(decoded);
});

app.post('/normal-json', (req, res) => {
  const obj = JSON.parse(req.body.data);
  res.json(obj);
});

app.get('/normal-xss', (req, res) => {
  const q = req.query.q;
  res.send('<h1>Search: ' + q + '</h1>');
});

app.listen(3000);
