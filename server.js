require('dotenv').config();
const client = require('twilio')(process.env.ACCOUNTSID, process.env.AUTH_TOKEN);
const { createHash } = require('crypto');
const express = require("express");
const { readFileSync, writeFileSync, existsSync } = require('fs');
const http = require('http');
const https = require('https');
const { certDue, newCSR, convertCRT } = require('./backend/controller/selfCheck');
const { submitCSR } = require('./backend/controller/spawn');
const apiRoutes = require('./backend/routes/api');
const { resolve } = require('path');
const httpsPort = 443;
const httpPort = 80;
const required_env_vars = ["SSL_KEY_PATH", "SSL_CERT_PATH", "SERVICE_NAME", "TWILIO_PHONE_NUMBER", "IT_PHONE", "ACCOUNTSID", "AUTH_TOKEN"];
if ( process.send === undefined ) {
  process.send = (msg) => {console.log(`App not launched by PM2, so not sending "${msg}" signal.`)};
}
let startfail = () => {
  process.send("ready");
  setTimeout(() => {
    console.log("Could not start server. Exiting gracefuly.");
    process.exit(0);
  }, 4000);
};
let missing = [];
required_env_vars.forEach( (e) => {
  if (!process.env[e]){
    console.log(`Missing environment variable ${e}`);
    missing.push(e);
  }
});
let textIT = async (msg) => {
  console.log(`Texting IT: "${msg}"`);
  let twilioRes = {};
  try {
    twilioRes = await client.messages.create({
      body: msg,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: process.env.IT_PHONE
    });
  } catch (error) {
    twilioRes = {isError: true, err: error.toString()};
  }
  if (twilioRes.isError === true) {
    console.log( `Text failed: ${ JSON.stringify(twilioRes) }` );
  } else {
    console.log( `Text Sent: ${twilioRes.sid}` );
  }
  return true;
}
let checkCert = async () => {
  let currentCertFile = process.env.SSL_CERT_PATH
  let certCheck = {isDue: true, daysLeft: 0, publicKey: "no cert"};
  let oldCertStr = "";
  if ( existsSync( currentCertFile ) ) {
    console.log("reading existing cert.");
    oldCertStr = readFileSync( currentCertFile ).toString();
    certCheck = await certDue( oldCertStr );
  } else {
    console.log("no existing cert. just creating a new one.");
  }
  if ( certCheck.isDue === true || process.env.FORCE_CERT_UPDATE === "true" ) {
    //remove the force update flag
    try {
      let envFile = readFileSync(".env").toString();
      envFile = envFile.replace(/FORCE_CERT_UPDATE=true/, "FORCE_CERT_UPDATE=false");
      writeFileSync(".env", envFile);
    } catch (error) {
      console.error(`Failed to update .env file: ${error.toString()}`);
      await textIT(`${process.env.SERVICE_NAME.toUpperCase()}:\nFailed to update .env file, cert will update on next reboot!\nError: ${error.toString()}`);
    }
    //time to get a new cert
    console.log("Reading config file for csr.");
    let config = readFileSync(`./certs/${process.env.SERVICE_NAME}.cfg`).toString();
    let newCert = newCSR( config, resolve("./certs/"), resolve(`./certs/${process.env.SERVICE_NAME}.key`) );
    if ( newCert.isError === true ) {
      await textIT(`${process.env.SERVICE_NAME.toUpperCase()}:\n${newCert.msg}: ${newCert.err}\nCert expires in ${certCheck.daysLeft} days.`);
      return false;
    }
    let certRes = await submitCSR( newCert.csr, createHash("sha256").update(certCheck.publicKey).digest('hex') );
    if ( certRes.isError === true ) {
      await textIT(`${process.env.SERVICE_NAME.toUpperCase()}:\n${certRes.msg}: ${certRes.err}\nCert expires in ${certCheck.daysLeft} days.`);
      return false;
    }
    //write new cert to file
    let now = new Date();
    let dateStr = `${now.getFullYear()}${(now.getMonth()+1).toString().padStart(2,"0")}${now.getDate().toString().padStart(2,"0")}`;
    let newCertStr = Buffer.from(certRes.b64Cert, "base64").toString();
    let newCertFile = resolve(`./certs/new-${dateStr}-${process.env.SERVICE_NAME}.crt`)
    let oldCertFile = resolve(`./certs/expired-${certCheck.expires}-${process.env.SERVICE_NAME}.crt`)
    if ( oldCertStr != "" ) {
      try {
        writeFileSync(oldCertFile, oldCertStr);
      } catch (error) {
        await textIT(`${process.env.SERVICE_NAME.toUpperCase()}:\nFailed to create old cert file: ${ error.toString() }\nCert expires in ${certCheck.daysLeft} days.`);
        return false;
      }
    }
    try {
      writeFileSync(newCertFile, newCertStr);
    } catch (error) {
      await textIT(`${process.env.SERVICE_NAME.toUpperCase()}:\nFailed to create old cert file: ${ error.toString() }\nCert expires in ${certCheck.daysLeft} days.`);
      return false;
    }
    let convertRes = convertCRT(newCertFile, currentCertFile);
    console.log(convertRes);
    if (convertRes.isError === true) {
      //revert back to old cert
      try {
        if (existsSync(oldCertFile)) {
          writeFileSync(currentCertFile, oldCertStr);
        }
      } catch (error) {
        await textIT(`${process.env.SERVICE_NAME.toUpperCase()}:\nFailed to revert back to old cert: ${ error.toString() }\nSERVICE IS DOWN!`);
      }
      await textIT(`${process.env.SERVICE_NAME.toUpperCase()}:\n${convertRes.msg}: ${convertRes.err}\nCert expires in ${certCheck.daysLeft} days.`);
      return false;
    }
    return true;
  }
  console.log(`Cert is not due. Cert expires in ${certCheck.daysLeft} days on ${certCheck.expires}.`);
  return false;
}
(async () => {
  if ( missing.length > 0) {
    await textIT(`${process.env.SERVICE_NAME.toUpperCase()}:\nMissing environment variables: ${missing.join(", ")}. Service not running!`);
    startfail();
  } else {
    let checkRes = await checkCert();
    if ( checkRes === true ) {
      console.log("New certificate installed.");
      await textIT(`${process.env.SERVICE_NAME.toUpperCase()}:\nNew certificate installed.`);
    }
    if ( !existsSync( process.env.SSL_CERT_PATH ) ) {
      console.log("No SSL certificate found. Exiting.");
      await textIT(`${process.env.SERVICE_NAME.toUpperCase()}:\nNo SSL certificate found. Service not running!`);
      startfail();
      return;
    }
    if ( !existsSync( process.env.SSL_KEY_PATH ) ) {
      console.log("No SSL key found. Exiting.");
      await textIT(`${process.env.SERVICE_NAME.toUpperCase()}:\nNo SSL key found. Service not running!`);
      startfail();
      return;
    }
    console.log("Starting server...");
    const httpsOptions = {
      key: readFileSync(process.env.SSL_KEY_PATH),
      cert: readFileSync(process.env.SSL_CERT_PATH)
    };
    const app = express();
    app.use(express.static("./public"));
    app.use(express.json());
    app.use('/api', apiRoutes); 
    app.get('/', (req, res) => {
        return res.sendFile(__dirname + "/public/views/main.html");
    });
    // Create HTTP server for redirect
    const httpServer = http.createServer((req, res) => {
      res.writeHead(301, { "Location": "https://" + req.headers['host'] + req.url });
      res.end();
    });
    httpServer.listen(80, () => {
      console.log(`HTTP server listening on http://localhost:${httpPort} for redirects`);
    });
    // Create HTTPS server
    const httpsServer = https.createServer(httpsOptions, app);
    httpsServer.listen(443, () => {
      console.log(`HTTPS server listening on https://localhost:${httpsPort}`);
      process.send("ready");
    });  
  }
})()