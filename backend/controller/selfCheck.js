const { KJUR, X509 } = require('jsrsasign');
const { writeFileSync, readFileSync, existsSync, unlinkSync } = require('fs');
const { convertTimestamp, cleanUp } = require('./tools');
const { execSync } = require('child_process');
const { join } = require('path');
e = {};
e.certDue = async (certStr) => {
    const cert = new X509();
    cert.readCertPEM(certStr);
    let oneDay = 24 * 60 * 60 * 1000;
    let notAfter = convertTimestamp(cert.getNotAfter());
    if (notAfter.isError === true) {
      return {isDue: false, msg: notAfter.msg};
    }
    let expires = notAfter.timestamp;
    let delta = Math.round(Math.abs(expires.getTime() - (new Date()).getTime())/oneDay);
    let publicKey = Buffer.from(cert.getSPKI(), "hex").toString('base64');
    let expireStr = `${expires.getFullYear()}-${(expires.getMonth()+1).toString().padStart(2,"0")}-${expires.getDate().toString().padStart(2,"0")}`;
    if ( delta < 14 ) {
      return {isDue: true, daysLeft: delta, expires: expireStr, publicKey: publicKey};
    }
    return {isDue: false, daysLeft: delta, expires: expireStr, publicKey: publicKey};
};
e.newCSR = ( config, cwd, keypath ) => {
  config = config.replace(/^\[\s*req\s*\]\s*(\r\n|\n)/,"[ req ]\r\nprompt = no\r\n");
  let subjectText = /\[\s*subject\s*\][^\[]+/.exec(config)[0];
  config = config.replace(subjectText, "[ subject ]\r\n");
  subjectText = subjectText.split(/(\r\n|\n)/).filter( e => /_default/.test(e)).join("\r\n").replace(/_default/g,"");
  config = config.replace("[ subject ]", `[ subject ]\r\n${subjectText}\r\n`);
  try {
    writeFileSync( join(cwd, "tempConfig.cfg"), config);
  } catch (error) {
    return {isError: true, msg: "Could not write config file.", err: error.toString()};
  }
  let now = new Date();
  let dateStr = `${now.getFullYear()}${(now.getMonth()+1).toString().padStart(2,"0")}${now.getDate().toString().padStart(2,"0")}`;
  let output = "";
  let csrPath = join(cwd, `${dateStr}-CSR.csr`);
  if ( !existsSync( csrPath ) ) {
    try {
      output = execSync(`openssl req -new -config ${join(cwd, "./tempConfig.cfg")} -key ${keypath} -out ${join(cwd,  `./${dateStr}-CSR.csr`)}`);
    } catch (error) {
      output = error.toString();
    }
  }
  if ( !existsSync( csrPath ) ) {
    return {isError: true, msg:"CSR file was not written.", err: output};
  }
  return {isError: false, msg: output, csr: readFileSync(csrPath).toString()};
}
e.convertCRT = ( crtPath, pemPath ) => {
  let crtStr = "";
  try {
    crtStr = readFileSync(crtPath).toString();
  } catch (error) {
    return {isError: true, msg: "Could not read CERT file.", err: error.toString()};
  }
  if ( /^-+BEGIN CERTIFICATE/.test(crtStr)  ) {
    //no converstion needed.
    try {
      writeFileSync(pemPath, crtStr);
    } catch (error) {
      return {isError: true, msg: "Could not write PEM file.", err: error.toString()};
    }
    return {isError: false, msg: "No conversion needed."};
  }
  let command = `openssl x509 -inform der -in "${crtPath}" -out "${pemPath}"`;
  let output = "";
  if ( existsSync(pemPath) ) {
    let deleteRes = cleanUp(pemPath);
    if ( deleteRes.isError === true ) {
      console.log("Could not delete existing PEM file: ", deleteRes.err); 
      return {isError: true, msg: "Could not delete existing PEM file.", err: deleteRes.err};
    }
  }
  try {
    output = execSync(command);
  } catch (error) {
    output = error.toString();
  }
  if ( existsSync(pemPath) ) {
    return {isError: false, msg: output};
  }
  return {isError: true, msg: `${pemPath} does not exist.`, err: output};
}
module.exports = e;