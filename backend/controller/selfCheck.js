const { KJUR, X509 } = require('jsrsasign');
const { writeFileSync, readFileSync, existsSync } = require('fs');
const { execSync } = require('child_process');
const { join } = require('path');
e = {};
e.certDue = (certStr) => {
    const cert = new X509();
    cert.readCertPEM(certStr);
    let oneDay = 24 * 60 * 60 * 1000;
    let expires = new Date(cert.getNotAfter());
    let delta = Math.round(Math.abs(expires.getTime() - (new Date()).getTime())/oneDay);
    if ( delta < 14 ) {
      let expireStr = `${expires.getFullYear()}-${(expires.getMonth()+1).toString().padStart(2,"0")}-${expires.getDate().toString().padStart(2,"0")}`;
      return {isDue: true, daysLeft: delta, expires: expireStr, publicKey: Buffer.from(cert.getSPKI(), "hex").toString('base64')};
    }
    return {isDue: false};
};
e.newCSR = ( config, cwd, keypath ) => {
  let config = config.replace(/^\[\s*req\s*\]\s*\n/,"[ req ]\nprompt = no\n");
  try {
    writeFileSync( join(cwd, "tempConfig.cnf"), config);
  } catch (error) {
    return {isError: true, msg: "Could not write config file.", err: error.toString()};
  }
  let now = new Date();
  let dateStr = `${now.getFullYear()}${(now.getMonth()+1).toString().padStart(2,"0")}${now.getDate().toString().padStart(2,"0")}`;
  let output = "";
  let csrPath = join(cwd, `${dateStr}-CSR.csr`);
  if ( !existsSync( csrPath ) ) {
    try {
      output = execSync(`openssl req -new -config ./tempConfig.cnf -key ${keypath} -out ./${dateStr}-CSR.csr`, {cwd: cwd});
    } catch (error) {
      output = error.toString();
    }
  }
  if ( !existsSync( csrPath ) ) {
    return {isError: true, msg:"CSR file was not written.", err: output};
  }
  return {isError: false, msg: output, csr: readFileSync(csrPath).toString()};
}
module.exports = e;