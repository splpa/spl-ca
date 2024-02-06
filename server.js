require('dotenv').config();
const client = require('twilio')(process.env.ACCOUNTSID, process.env.AUTH_TOKEN);
const express = require("express");
const { readFileSync, writeFileSync } = require('fs');
const http = require('http');
const https = require('https');
const { certDue, newCSR, convertCRT } = require('./backend/controller/selfCheck');
const { submitCSR } = require('./backend/spawn/spawn');
const apiRoutes = require('./backend/routes/api');
const { resolve } = require('path');
const httpsPort = 443;
const httpPort = 80;
const required_env_vars = ["SSL_KEY_PATH", "SSL_CERT_PATH", "SERVICE_NAME", "TWILIO_PHONE_NUMBER", "IT_PHONE", "ACCOUNTSID", "AUTH_TOKEN"];
required_env_vars.forEach( (e) => {
  if (!process.env[e]){
    console.log(`Missing environment variable ${e}`);
    process.exit(1);
  }
});
let textIT = (msg) => {
  client.messages
    .create({
        body: msg,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: process.env.IT_PHONE
    })
    .then(message => {
        console.log("Text message sent to IT", message.sid);
      }
    );
};
let checkCert = async () => {
  let certCheck = certDue( readFileSync( process.env.SSL_CERT_PATH ).toString() );
  if ( certCheck.isDue === true || process.env.FORCE_CERT_UPDATE === "true" ) {
    //time to get a new cert
    let config = readFileSync(`./certs/${process.env.SERVICE_NAME}.cfg`).toString();
    let newCert = newCSR( config, resolve("./certs/"), resolve(`./certs/${process.env.SERVICE_NAME}.key`) );
    if ( newCert.isError === true ) {
      textIT(`${process.env.SERVICE_NAME}. ${newCert.msg}: ${newCert.err}\nCert expires in ${certCheck.daysLeft} days.`);
      return false;
    }
    let certRes = await submitCSR( newCert.csr, certCheck.publicKey );
    if ( certRes.isError === true ) {
      textIT(`${process.env.SERVICE_NAME}. ${certRes.msg}: ${certRes.err}\nCert expires in ${certCheck.daysLeft} days.`);
      return false;
    }
    //write new cert to file
    let now = new Date();
    let dateStr = `${now.getFullYear()}${(now.getMonth()+1).toString().padStart(2,"0")}${now.getDate().toString().padStart(2,"0")}`;
    let currentCertFile = process.env.SSL_CERT_PATH
    console.log(certRes);
    let newCertStr = Buffer.from(certRes.b64Cert, "base64").toString();
    let newCertFile = resolve(`./certs/new-${dateStr}-${process.env.SERVICE_NAME}.crt`)
    let oldCertFile = resolve(`./certs/expired-${certCheck.expires}-${process.env.SERVICE_NAME}.crt`)
    let oldCertStr = readFileSync(currentCertFile).toString();
    try {
      writeFileSync(oldCertFile, oldCertStr);
    } catch (error) {
      textIT(`${process.env.SERVICE_NAME}. Failed to create old cert file: ${error}\nCert expires in ${certCheck.daysLeft} days.`);
      return false;
    }
    try {
      writeFileSync(newCertFile, newCertStr);
    } catch (error) {
      textIT(`${process.env.SERVICE_NAME}. Failed to create old cert file: ${error}\nCert expires in ${certCheck.daysLeft} days.`);
      return false;
    }
    let convertRes = convertCRT(newCertFile, currentCertFile);
    if (convertRes.isError === true) {
      textIT(`${process.env.SERVICE_NAME}. ${convertRes.msg}: ${convertRes.err}\nCert expires in ${certCheck.daysLeft} days.`);
      return false;
    }
    return true;
  }
  console.log(`Cert is not due. Cert expires in ${certCheck.daysLeft} days on ${certCheck.expires}.`);
  return false;
}

if ( checkCert() === true ) {
  textIT(`${process.env.SERVICE_NAME}. New certificate installed.`);
  console.log("New certificate installed.");
}

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
