require('dotenv').config();
const express = require("express");
const { readFileSync } = require('fs');
const http = require('http');
const https = require('https');
const apiRoutes = require('./backend/routes/api');
const httpsPort = 443;
const httpPort = 80;
const required_env_vars = ["SSL_KEY_PATH", "SSL_CERT_PATH"];
required_env_vars.forEach( (e) => {
  if (!process.env[e]){
    console.log(`Missing environment variable ${e}`);
    process.exit(1);
  }
});
// testing:{
//   const {X509, KJUR } = require("jsrsasign");
//   const { submitCSR, retreiveCert } = require("./backend/spawn/spawn");
//   const certsRoot = "./";
//   let csrText = readFileSync('./test-splrootca.req').toString();
//   let csr = new KJUR.asn1.csr.CSRUtil.getParam( csrText );
//   let csrInfo = new KJUR.asn1.csr.CertificationRequest(csr);
//   let csrPublicKey = csrInfo.params.sbjpubkey.replace(/(\r|\n|-+(BEGIN|END) PUBLIC KEY-+)/g,"");
//   let certStr = readFileSync('./test-splrootca.crt').toString();
//   cert = new X509();
//   cert.readCertPEM(certStr);
//   let altNames = cert.getExtSubjectAltName().array.map( (e) => {return `${e.dns?`DNS: ${e.dns}`: `IP: ${e.ip}`}`}).join(", ");
//   let subjectStr = cert.getSubjectString();
//   let certPublicKey = Buffer.from(cert.getSPKI(), "hex").toString('base64');
//   console.log("cert publicKey:", certPublicKey);
//   console.log("csr PublicKey:", csrPublicKey);
//   console.log("altNames:", altNames);
//   console.log("subjectStr:", subjectStr);
//   (async () => {
//     console.log( await submitCSR(csrText,csrPublicKey,"test") );
//   })()
//   //process.exit(0);
// }
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
