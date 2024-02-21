const { createHash } = require('crypto');
const { execSync } = require('child_process');
const express = require("express");
const { readFileSync, writeFileSync, existsSync, statSync, unlinkSync, copyFileSync } = require('fs');
const { resolve } = require('path');
const http = require('http');
const https = require('https');

require('dotenv').config();
if ( process.env.DB_PATH === undefined ) {
  process.env.DB_PATH = resolve("./Certificates.db");
} else {
  const stats = fs.statSync("/.env");
  const diffMins = (new Date() - stats.mtime) / 60000;
  if ( diffMins < 30 ) {
    console.log(`.env file recently modified. Recreating shotcut.`);
    unlinkSync(resolve("./3rd Party/SQLite Browser.lnk"));
  }
}
const { textIT } = require('./backend/controller/textIT');
const { certDue, newCSR, convertCRT } = require('./backend/controller/selfCheck');
const { submitCSR } = require('./backend/controller/spawn');
const cron = require('./backend/controller/cron');
const apiRoutes = require('./backend/routes/api');
const httpsPort = 443;
const httpPort = 80;
const required_env_vars = ["SSL_KEY_PATH", "SSL_CERT_PATH", "SERVICE_NAME", "TWILIO_PHONE_NUMBER", "IT_PHONE", "ACCOUNTSID", "AUTH_TOKEN"];
if ( process.send === undefined ) {
  process.send = (msg) => {console.log(`App not launched by PM2, so not sending "${msg}" signal.`)};
}
let returnCert = (req, res, certType) => {
  switch (certType) {
    case "pem":
      if ( !existsSync( process.env.SSL_CA_PEM_PATH ) ) {
        console.log(process.env)
        textIT(`${process.env.SERVICE_NAME.toUpperCase()}:\n pem file doesn't not exist ${process.SSL_CA_PEM_PATH}.`);
        return res.json({isError: true, msg: "CA.pem not found"});
      }
      return res.sendFile(process.env.SSL_CA_PEM_PATH);
    case "cer":
    case "crt":
    case "der":
      if ( !existsSync( process.env.SSL_CA_CER_PATH ) ) {
        textIT(`${process.env.SERVICE_NAME.toUpperCase()}:\n cer file doesn't not exist ${process.SSL_CA_CER_PATH}.`);
        return res.json({isError: true, msg: "CA.cer not found"});
      }
      return res.sendFile(process.env.SSL_CA_CER_PATH);
    default:
      textIT(`${process.env.SERVICE_NAME.toUpperCase()}:\n Invalid cert type ${certType}.\nRequest from ${req.ip.replace("::ffff:", "")} ${req.headers['user-agent']}`);
      return res.json({isError: true, msg: "Invalid cert type"});
  }
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
if ( !existsSync("./3rd Party/DB Browser for SQLite/") ) {
  if ( existsSync("./3rd Party/DB Browser for SQLite.zip") ) {
    try {
      execSync(`powershell Expand-Archive -Path '${resolve("./3rd Party/DB Browser for SQLite.zip")}' -DestinationPath '${resolve("./3rd Party/")}'`);
      console.log('Extraction complete');
    } catch (error) {
      console.error('Error extracting file:', error);
    }
  }
}
if ( existsSync("./3rd Party/DB Browser for SQLite/DB Browser for SQLite.exe") ) {
  const shortcutCommand = 
`$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut('${resolve("./3rd Party/SQLite Browser.lnk")}')
$Shortcut.TargetPath = '${resolve("./3rd Party/DB Browser for SQLite/DB Browser for SQLite.exe")}'
$Shortcut.Arguments = '\\"${process.env.DB_PATH}\\"'
$Shortcut.Save();`;
    try {
      execSync(`powershell.exe -Command "${shortcutCommand.replace(/\n/g,"; ")}"`, { stdio: 'inherit' });
      console.log('Shortcut created successfully');
      copyFileSync(resolve("./3rd Party/SQLite Browser.lnk"), resolve("./SQLite Browser.lnk"));
    } catch (error) {
      console.error('Error extracting file:', error);
    }
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
    app.get(/\/CA\.[a-z]*/, async (req, res) => {
      let ext = req.url.replace("/CA.", "");
      return await returnCert(req, res, ext);
    });
    cron.start();
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