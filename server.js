require('dotenv').config();
const express = require("express");
const { readFileSync } = require('fs');
const http = require('http');
const https = require('https');
const apiRoutes = require('./backend/routes/api');
const httpsPort = 443;
const httpPort = 80;

const app = express();

app.use(express.static("./public"));
app.use(express.json());
app.use('/api', apiRoutes); 
app.get('/', (req, res) => {
    return res.sendFile(__dirname + "/public/views/main.html");
});

const httpsOptions = {
  key: readFileSync(process.env.SSL_KEY_PATH),
  cert: readFileSync(process.env.SSL_CERT_PATH)
};

// Create HTTPS server
const httpsServer = https.createServer(httpsOptions, app);

httpsServer.listen(443, () => {
  console.log(`HTTPS server listening on https://localhost:${httpsPort}`);
});

// Create HTTP server for redirect
const httpServer = http.createServer((req, res) => {
  res.writeHead(301, { "Location": "https://" + req.headers['host'] + req.url });
  res.end();
});

httpServer.listen(80, () => {
  console.log(`HTTP server listening on http://localhost:${httpPort} for redirects`);
});
