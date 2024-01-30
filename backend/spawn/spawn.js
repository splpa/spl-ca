const { spawn } = require('child_process');
const { join, resolve } = require('path');
const { createHash, sign } = require('crypto');
const { cleanUp } = require('../controller/cleanUp');
const { readFileSync, writeFileSync, existsSync } = require('fs');
const certsRoot = join("./", 'test');
let e = {};
let spawnAsync = async (command, args, eventId) => {
  console.log(`${eventId}: running "${command} ${args.join(" ")}"`)
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
e.retrieveCert = async (requestId, publicKey, eventId) => {
  let certPath = join(certsRoot, `${createHash("sha256").update(publicKey).digest('hex')}.crt`);
  let retrieveRes = ""; 
  try {
    retrieveRes = await spawnAsync("certreq", ["-retrieve", "-config", "SPLROOTCA\\PathologyAssociates-SPLROOTCA-CA", requestId, certPath], eventId);
  } catch (error) {
    console.log(`${eventId}: Error retrieving certificate. Error: ${error.toString()}`);
    return {isError: true, msg: "Error retrieving certificate.", msg: error.toString()};
  }
  if ( retrieveRes.includes("Certificate retrieved") ) {
    if ( existsSync( certPath ) ) {
      let b64Cert = "";
      try {
        b64Cert = readFileSync(certPath).toString('base64');
      } catch (error) {
        console.log(`${eventId}: Error reading certificate. Error: ${error.toString()}`);
        return {isError: true, msg: "Error reading certificate.", err: error.toString()};
      }
      return {isError: false, msg: "Certificate retrieved.", b64Cert: b64Cert};
    }
    console.log(`${eventId}: Certificate was not retrieved, it did not exist.`);
    return {isError: true, msg: "Certificate was not retrieved, it did not exist."};
  }
  console.log(`${eventId}: Failed to retrieve certificate. Output: ${retrieveRes.toString()}`);
  return {isError: true, msg: "Failed to retrieve certificate.", err: retrieveRes.toString()};
}

e.submitCSR = async (csrText, publicKey, eventId) => {
  let reqPath = join(certsRoot, `${createHash("sha256").update(publicKey).digest('hex')}.req`);
  if ( existsSync( reqPath ) ) {
    let cleanUpRes = cleanUp(reqPath, eventId);
    if ( cleanUpRes.isError === true ) {
      return {isError: true, msg: "Error cleaning up old CSR.", err: cleanUpRes.err};
    }
  }
  try {
    writeFileSync( reqPath, csrText );
  } catch (error) {
    console.log(`${eventId}: Error writing CSR to file. Error: ${error.toString()}`);
    return {isError: true, msg: "Error writing CSR to file.", err: error.toString()};
  }
  if ( existsSync( reqPath ) ) {
    let submitRes = "";
    try {
      submitRes = await spawnAsync("certreq", ["-submit", "-config", "SPLROOTCA\\PathologyAssociates-SPLROOTCA-CA", reqPath ], eventId);
    } catch (error) {
      console.log(`${eventId}: Error submitting CSR. Error: ${error.toString()}`);
      return {isError: true, msg: "Error submitting CSR.", err: error.toString()};
    }
    if ( submitRes.includes("Certificate request is pending") === true && /RequestId: \d+/.test(submitRes) == true ) {
      let requestId = Number(submitRes.match(/(?<=RequestId: )\d+/)[0]);
      console.log(`${eventId}: Certificate request is pending. RequestID: ${requestId}`);
      let signed = await signCert(requestId, publicKey, eventId);
      if (signed.isError === false) {
        console.log(`${eventId}: Certificate signed.`);
        return {isError: false, msg: "Certificate signed.", b64Cert: signed.b64Cert}; 
        //code here
      }
      return {isError: true, msg: signed.msg, err: signed.err};
    }
    console.log(`${eventId}: Failed to submit CSR. Output: ${submitRes.toString()}`);
    return {isError: true, msg: "Failed to submit CSR.", err: submitRes.toString()};
  }
  console.log(`${eventId}: CSR file did not exist.`);
  return {isError: true, msg: "CSR file did not exist."};
}

let signCert = async (requestId, publicKey, eventId) => {
  let signRes = "";
  try {
    signRes = await spawnAsync("certutil", [ "-config", "SPLROOTCA\\PathologyAssociates-SPLROOTCA-CA", "-resubmit", requestId], eventId);  
  } catch (error) {
    console.log(`${eventId}: Error signing CSR. Error: ${error.toString()}`);
    return {isError: true, msg: "Error signing CSR.", err: error.toString()};
  }
  if ( signRes.includes("Certificate issued.") ) {
    let certRetrived = "";
    try {
      certRetrived = await e.retrieveCert(requestId, publicKey, eventId);  
    } catch (error) {
      console.log(`${eventId}: Error calling retrie certificate. Error: ${error.toString()}`);
      return {isError: true, msg: "Error retrieving certificate", err: error.toString()};
    }
    if ( certRetrived.isError === false ) {
      return { isError: false, msg: "Certificate retrieved.", b64Cert: certRetrived.b64Cert };
    }
    return { isError: true, msg: certRetrived.msg, err: certRetrived.err };
  }
  console.log(`${eventId}: Failed to issue certificate. Output: ${signRes.toString()}`);
  return {isError: true, msg: "Failed to issue certificate", err: signRes.toString()};
}
module.exports = e;