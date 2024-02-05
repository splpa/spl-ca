const { spawn } = require('child_process');
const { join } = require('path');
const { createHash } = require('crypto');
const { cleanUp } = require('../controller/cleanUp');
const { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync } = require('fs');
const certsRoot = join("./", 'temp');
let checkCertRoot = () => {
  if ( !existsSync(certsRoot) ) {
    try {
      mkdirSync(certsRoot);
      return true;
    } catch (error) {
      console.log("Error creating certsRoot directory: ", error.toString());
    }
    return false;
  }
  return true;
}
let e = {};
let spawnAsync = async (command, args) => {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args);
    let output = '';
    child.stdout.on('data', (data) => {
      output += data.toString();
    });
    child.stderr.on('data', (data) => {
      output += data.toString();
    });
    child.on('close', (code) => {
      if (code === 0) {
        resolve(output);
      } else {
        reject(new Error(`Command failed with exit code ${code}: ${output}`));
      }
    });
    child.on('error', (err) => {
      reject(err);
    });
  });
}
e.retrieveCert = async (requestId, publicKey) => {
  let certPath = join(certsRoot, `${createHash("sha256").update(publicKey).digest('hex')}.rsp`);
  if (existsSync (certPath) ) {
    try {
      unlinkSync(certPath);
    } catch (error) {
      console.log("Error deleting certificate file: ", error.toString());
    }
  }
  let retrieveRes = ""; 
  try {
    retrieveRes = await spawnAsync("certreq", ["-retrieve", "-f", "-config", "SPLROOTCA\\PathologyAssociates-SPLROOTCA-CA", requestId, certPath]);
  } catch (error) {
    console.log("Error retrieving certificate: ", error.toString());
    return {isError: true, msg: "Error retrieving certificate.", msg: error.toString()};
  }
  if ( retrieveRes.includes("Certificate retrieved") ) {
    if ( existsSync( certPath ) ) {
      let b64Cert = "";
      try {
        b64Cert = readFileSync(certPath).toString('base64');
      } catch (error) {
        return {isError: true, msg: "Error reading certificate.", err: error.toString()};
      }
      await cleanUp(certPath);
      return {isError: false, msg: "Certificate retrieved.", b64Cert: b64Cert};
    }
    return {isError: true, msg: "Certificate was not retrieved, it did not exist."};
  } else if ( retrieveRes.includes("Certificate request is pending") ) {
    return {isError: false, isPending: true, msg: "Certificate is pending."}
  }
  console.log("Failed to retrieve certificate: ", retrieveRes);
  return {isError: true, msg: "Failed to retrieve certificate.", err: retrieveRes.toString()};
}

e.submitCSR = async (csrText, publicKey)=> {
  let reqPath = join(certsRoot, `${createHash("sha256").update(publicKey).digest('hex')}.req`);
  if ( existsSync( reqPath ) ) {
    let cleanUpRes = cleanUp(reqPath);
    if ( cleanUpRes.isError === true ) {
      return {isError: true, msg: "Error cleaning up old CSR.", err: cleanUpRes.err};
    }
  }
  if ( checkCertRoot() === false ) {
    return {isError: true, msg: "Error creating required directory, Admins must investigate."};
  }
  try {
    writeFileSync( reqPath, csrText );
  } catch (error) {
    return {isError: true, msg: "Error writing CSR to file.", err: error.toString()};
  }
  if ( existsSync( reqPath ) ) {
    let submitRes = "";
    try {
      submitRes = await spawnAsync("certreq", ["-submit", "-config", "SPLROOTCA\\PathologyAssociates-SPLROOTCA-CA", reqPath ]);
    } catch (error) {
      await cleanUp(reqPath)
      return {isError: true, msg: "Error submitting CSR.", err: error.toString()};
    }
    await cleanUp(reqPath);
    if ( submitRes.includes("Certificate request is pending") === true && /RequestId: \d+/.test(submitRes) == true ) {
      let requestId = Number(submitRes.match(/(?<=RequestId: )\d+/)[0]);
      let signed = await signCert(requestId, publicKey);
      if (signed.isError === false) {
        return {isError: false, msg: "Certificate signed.", b64Cert: signed.b64Cert, requestId: requestId}; 
      }
      return {isError: true, msg: signed.msg, err: signed.err, requestId: requestId};
    }
    return {isError: true, msg: "Failed to submit CSR.", err: submitRes.toString()};
  }
  return {isError: true, msg: "CSR file did not exist."};
}

let signCert = async (requestId, publicKey) => {
  let signRes = "";
  try {
    signRes = await spawnAsync("certutil", [ "-config", "SPLROOTCA\\PathologyAssociates-SPLROOTCA-CA", "-resubmit", requestId]);  
  } catch (error) {
    return {isError: true, msg: "Error signing CSR, Admins must investigate.", err: error.toString()};
  }
  if ( signRes.includes("Certificate issued.") ) {
    let certRetrived = "";
    try {
      certRetrived = await e.retrieveCert(requestId, publicKey);  
    } catch (error) {
      return {isError: true, msg: "Error retrieving certificate", err: error.toString()};
    }
    if ( certRetrived.isError === false ) {
      return { isError: false, msg: "Certificate retrieved.", b64Cert: certRetrived.b64Cert };
    }
    return { isError: true, msg: certRetrived.msg, err: certRetrived.err };
  }
  return {isError: true, msg: "Failed to issue certificate", err: signRes.toString()};
}
module.exports = e;