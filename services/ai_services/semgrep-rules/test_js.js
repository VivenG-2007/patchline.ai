const crypto = require('crypto');
const { exec, execFile, spawn } = require('child_process');
const fs = require('fs');

const userId = req.query.id;

// ruleid: sqli-js-template
db.query(`SELECT * FROM users WHERE id = ${userId}`);
// ok: sqli-js-template
db.query('SELECT * FROM users WHERE id = ?', [userId]);

// ruleid: sqli-js-concat
db.query("SELECT * FROM users WHERE id = " + userId);
// ok: sqli-js-concat
db.query("SELECT * FROM users WHERE id = ?", [userId]);

// ruleid: sqli-js-indirect-concat
let query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);
// ok: sqli-js-indirect-concat
let query2 = "SELECT * FROM users WHERE id = ?";
db.query(query2, [userId]);

// ruleid: sqli-js-multi-concat
let query = "SELECT * FROM users WHERE " + userId;
query = query + " AND active = 1";
db.query(query);
// ok: sqli-js-multi-concat
let query5 = "SELECT * FROM users WHERE id = ?";
db.query(query5, [userId]);

const src = req.query.id;
// ruleid: sqli-js-taint
db.query(src);

// ruleid: xss-innerhtml-concat
el.innerHTML = "<b>" + userInput + "</b>";
// ok: xss-innerhtml-concat
el.textContent = userInput;

// ruleid: xss-document-write
document.write(userInput);
// ok: xss-document-write
console.log(userInput);

// ruleid: xss-express-send-concat
res.send("<p>" + userInput + "</p>");
// ok: xss-express-send-concat
res.json({ message: userInput });

// ruleid: xss-insertadjacenthtml
el.insertAdjacentHTML("beforeend", "<b>" + userInput + "</b>");
// ok: xss-insertadjacenthtml
el.insertAdjacentText("beforeend", userInput);

// ruleid: xss-outerhtml-assignment
el.outerHTML = "<b>" + userInput + "</b>";
// ok: xss-outerhtml-assignment
el.textContent = userInput;

// ruleid: xss-dom-sink-eval
eval(userInput);
// ok: xss-dom-sink-eval
JSON.parse(userInput);

// ruleid: xss-innerhtml-indirect
let html = "<b>" + userInput;
el.innerHTML = html;

// ruleid: cmdi-js-exec-template
exec(`ping ${host}`);
// ok: cmdi-js-exec-template
execFile("ping", [host]);

// ruleid: cmdi-js-exec-concat
exec("ping " + host);
// ok: cmdi-js-exec-concat
execFile("ping", [host]);

// ruleid: cmdi-js-indirect
let cmd = "ping " + host;
exec(cmd);
// ok: cmdi-js-indirect
let cmd2 = ["ping", host];
execFile(cmd2[0], [cmd2[1]]);

// ruleid: cmdi-js-execfile-array
execFile(userSuppliedBinary, args);
// ok: cmdi-js-execfile-array
execFile("/bin/ls", args);

// ruleid: path-traversal-js-fs
fs.readFile(req.query.path, cb);
// ok: path-traversal-js-fs
fs.readFile("static/config.json", cb);

// ruleid: crypto-md5
const h1 = crypto.createHash("md5");
// ok: crypto-md5
const h1b = crypto.createHash("sha256");

// ruleid: crypto-sha1
const h2 = crypto.createHash("sha1");
// ok: crypto-sha1
const h2b = crypto.createHash("sha256");

// ruleid: crypto-rc4
const c1 = crypto.createCipheriv("rc4", key, iv);
// ok: crypto-rc4
const c1b = crypto.createCipheriv("aes-256-gcm", key, iv);

// ruleid: nosqli-mongodb-js-operator
collection.find({ $where: "this.id == " + userId });
// ok: nosqli-mongodb-js-operator
collection.find({ status: "active" });

// ruleid: log-forging-js
console.log(req.body);
// ok: log-forging-js
console.log("static message");

const searchTerm = location.search;
// ruleid: xss-js-taint
el.innerHTML = searchTerm;
