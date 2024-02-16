const { KJUR, X509, KEYUTIL, pemtohex } = require('jsrsasign');
const { updateRecord, getRecord, registerCert } = require('../sqlite/db');
const { retrieveCert, submitCSR } = require('./spawn');
const { convertTimestamp } = require('./tools');
const { readFileSync } = require('fs');
const oneDay = 1000 * 60 * 60 * 24;
e = {};
let markPending = async (record, eventId) => {
  record.logs.unshift(eventId);
  record.pending = true;
  return await updateRecord(record, eventId);
};
let markActive = async (record, eventId) => {
  record.active = true,
  record.pending = false,
  record.updateIP = false,
  record.updateSubjectStr = false,
  record.updateAltNames = false,
  record.approveAll = false,
  record.logs.unshift(eventId);
  return await updateRecord(record, eventId);
}
let validCSR = async (record, eventId) => {
  let certStr = null;
  let cert = null;
  if ( record.requestID > 0 && record.currentCert !== "" ) {
    console.log(`${eventId}: Checking with CA for cert for requestID ${record.requestID} to verify cert expiration.`);
    //first check if cert already exists
    let certRes = await retrieveCert(record.requestID, createHash("sha256").update(record.publicKey).digest('hex'), eventId);
    if ( certRes.isError ){
      return { isValid:false, msg: certRes.msg }
    }
    certStr = Buffer.from(certRes.b64Cert, "base64").toString();
  } else if ( record.currentCert !== "" ){
    certStr = Buffer.from(record.currentCert, "base64").toString();
  } else {
    //no cert exist only continue if admin has approved this key
    if ( record.approveAll !== true ) {
      console.log(`${eventId}: Pending Admin approval for ${record.publicKey}.`);
      return {isValid:false, msg: "Admin approval is required to sign certificate."}
    }
  } 
  if ( record.approveAll ==! true ) {
    cert = new X509();
    try {
      cert.readCertPEM(certStr); 
      console.log(certStr)
    } catch (error) {
      console.log(`${eventId}: Error parsing certificate text. Error: ${error.toString()}`);
      return {isValid:false, msg: "Error parsing certificate text. Admins will need to investigate."};
    }
    let certAltNames = cert.getExtSubjectAltName().array.map( (e) => {return `${e.dns?`DNS: ${e.dns}`: `IP: ${e.ip}`}`}).join(", ");
    let certSubjectStr = cert.getSubjectString();
    let certPublicKey = Buffer.from(cert.getSPKI(), "hex").toString('base64');
    let notAfter = convertTimestamp(cert.getNotAfter());//YYMMDDHHMMSSZ OR YYYYMMDDHHMMSSZ
    if ( notAfter.isError === true ) {
      return {isValid:false, msg: "Could not verify expiration date. Admins will need to investigate", err: notAfter.err};
    }
    let expires = notAfter.timestamp;
    let certDaysToExpire = Math.round(Math.abs( expires.getTime() - new Date().getTime()) / oneDay);
    if ( certDaysToExpire > 14 ) {
      return {isValid:false, msg: `Certificate is not near expiration, cert has ${certDaysToExpire} days left. Try again within 14 days of expiration.`};
    }
    if ( record.updateSubjectStr !== true ) {
       if ( record.subjectStr !== certSubjectStr ) {
        return {isValid:false, msg: "CSR subject does not match Certficate subject for this key. Revert to previous configuration or have admin approve new subjectStr then try again."};
       }
    }
    if ( record.updateAltNames !== true ) {
      if ( record.altNames !== certAltNames ) {
        return {isValid:false, msg: "CSR altNames does not match Certficate altNames for this key. Revert to previous configuration or have admin approve new altNames then try again."};
      }
    }
    if ( record.updatePublicKey !== true ) {
      if ( record.publicKey !== certPublicKey ) {
        return {isValid:false, msg: "CSR publicKey does not match Certficate publicKey for this key. Revert to previous configuration or have admin approve new publicKey then try again."};
      }
    }
  }
  return {isValid:true, msg: "CSR is valid."};
}
let extractCertData = (cert) => {
  try {
    let altNames = cert.getExtSubjectAltName().array.map( (e) => {return `${e.dns?`DNS: ${e.dns}`: `IP: ${e.ip}`}`}).join(", ");
    let subjectStr = cert.getSubjectString();
    let publicKey = Buffer.from(cert.getSPKI(), "hex").toString('base64');
    let notAfter = convertTimestamp(cert.getNotAfter());//YYMMDDHHMMSSZ OR YYYYMMDDHHMMSSZ
    let expires = notAfter.timestamp;
    let certDaysToExpire = Math.round(Math.abs( expires.getTime() - new Date().getTime()) / oneDay);
    return {isError:false, altNames:altNames, subjectStr:subjectStr, publicKey:publicKey, expires:expires, certDaysToExpire:certDaysToExpire};
  } catch (error) {
    return {isError: true, msg: "Error extracting data cert.", err: error.toString()};
  }
}
let extractAndValidateCert = (clientCertText) => {
  let cert = new X509();
  try {
    cert.readCertPEM(clientCertText);
  } catch (error) {
    return {isError: true, msg: "Failed to parse cert", err: error.toString()};
  }
  let publicKey = Buffer.from(cert.getSPKI(), 'hex').toString('base64');
  let certValid = false;
  try { 
    let sig2 = new KJUR.crypto.ECDSA();
    sig2.setPublicKeyHex(cert.getSPKIHex());
    //sig2.init(clientCertText);
    sig2.updateString(Buffer.from(clientCertText));
    certValid = sig.verify(sigValueHex);
  } catch (error) {
    return {isError: true, msg: "Error Verifying Signature", err: error.toString()};
  }
  return {isError: false, certValid:certValid, publicKey:publicKey, cert: cert};
}
e.renew = async (req, res, csrText, eventId) => {
  if (KJUR.asn1.csr.CSRUtil.verifySignature( csrText ) !== true ) {
    console.log(`${eventId}: CSR WAS TAMPERTED WITH. ${JSON.stringify(csrText)}`);
    //email alert
    return res.json({isError: true, msg: "THE CSR SENT HAS BEEN TAMPERED WITH!"});
  }
  let csr = KJUR.asn1.csr.CSRUtil.getParam( csrText );
  let csrInfo = new KJUR.asn1.csr.CertificationRequest(csr);
  let sourceIP = req.ip.replace("::ffff:", "");
  let publicKey = csrInfo.params.sbjpubkey.replace(/(\r|\n|-+(BEGIN|END) PUBLIC KEY-+)/g,"");
  let subjectStr = csrInfo.params.subject.str;
  let altNameIndx = csrInfo.params.extreq.map( e => {return e.extname;}).indexOf("subjectAltName");
  let altNames = csrInfo.params.extreq[altNameIndx].array.map( e => {return `${e.dns?`DNS: ${e.dns}`: `IP: ${e.ip}`}`}).join(", ");
  let match = await getRecord( publicKey, eventId);
  if ( match ) {
    if ( match.pending === true && (match.approveAll !== true && match.updateIP !== true && match.updateSubjectStr !== true && match.updateAltNames !== true) ) {
      console.log(`${eventId}: CSR was already submitted and is pending Admin approval.`);
      return res.json({isError: true, msg: "CSR was already submitted and is pending Admin approval."});
    }
    if ( match.createdIP !== sourceIP && match.updateIP !== true && match.approveAll !== true ) {
      console.log(`${eventId}: CSR was created from a different IP.`);
      markPending(match, eventId);
      return res.json({isError: true, msg: "CSR was created from a different IP. Have admin approve new IP then try again."});
    }
    if ( match.subjectStr !== subjectStr && match.updateSubjectStr !== true && match.approveAll !== true ) {
      console.log(`${eventId}: CSR subject does not match approved subject for this key.`);
      markPending(match, eventId);
      return res.json({isError: true, msg: "CSR subject does not match approved subject for this key. Revert to previous configuration or have admin approve new subjectStr then try again."});
    }
    if ( match.altNames !== altNames && match.updateAltNames !== true && match.approveAll !== true ) {
      console.log(`${eventId}: CSR altNames does not match approved altNames for this key.`);
      markPending(match, eventId);
      return res.json({isError: true, msg: "CSR altNames does not match approved altNames for this key. Revert to previous configuration or have admin approve new altNames then try again."})
    }    
    console.log(`${eventId}: CSR is valid a format.`);
    let csrCheck = await validCSR( match, eventId );
    if ( csrCheck.isValid === false ) {
      markPending(match, eventId);
      return res.json({isError: true, msg: csrCheck.msg});
    }
    //time to submit the CSR
    let csrRes = await submitCSR(csrText, createHash("sha256").update(publicKey).digest('hex'));
    if ( csrRes.isError === true ) {
      if (csrRes.requestId) match.requestID = csrRes.requestId;
      markPending(match, eventId);
      console.log(`${eventId}: ${csrRes.msg} ${csrRes.err}` );
      return res.json({isError: true, msg: csrRes.msg});
    }
    match.subjectStr = subjectStr;
    match.altNames = altNames;
    match.createdIP = sourceIP;
    match.currentCert = csrRes.b64Cert;
    match.requestID = csrRes.requestId;
    let markRes = await markActive(match, eventId);
    if (markRes.changes !== 1) {
      console.log(`${eventId}: Error marking record as active.`);
    }
    return res.json({isError: false, msg: "CSR accepted and signed.", b64Cert: csrRes.b64Cert});
  } else {
    let created = new Date();
    let newRecord = {
      publicKey: publicKey,
      active: false,
      pending: true,
      currentCert: "",
      created: created - 0,
      createdTimestamp: `${created.toLocaleDateString()} ${created.toLocaleTimeString().replace(/:\d{2} /g,"")}`,
      requestID: -1,
      createdIP: sourceIP,
      updateIP: false,
      subjectStr: "",
      updateSubjectStr: false,
      altNames: "",
      updateAltNames: false,
      approveAll: false,
      logs:[eventId]
    };
    console.log(`${eventId}: New record added to DB. Requires admin approval.`, await updateRecord(newRecord, eventId) );
    return res.json({isError: true, msg: "Key is not in approved list. Have admin approve the new key."});
  }
}
e.register = async (b64Cert, b64Sig, res, eventId) => {
  let ogCertStr = Buffer.from(b64Cert, "base64").toString();
  let signedCertStr = Buffer.from(b64Sig, "base64").toString();
  let ogCert = extractAndValidateCert(ogCertStr);
  let signedCert = extractAndValidateCert(signedCertStr);
  // console.log("ogCertStr:", ogCertStr);
  console.log("signedCertStr:", signedCertStr);
  // console.log("OG:", ogCert);
  console.log("sig:", signedCert);
  return res.json({isError: false, msg: "Route is not configured yet."});
};
e.registerTest = async (req, res) => {
  console.log(Object.keys(req.body));
  let clientCert = new X509();
  let clientCertText = req.body.pemCert;
  try {
    clientCert.readCertPEM(clientCertText);
  } catch (error) {
    return res.json({isError: true, msg: "Failed to parse cert", err: error.toString()});
  }
  let clientSignatureHex = req.body.signatureHex;
  let clientPublicKey = KEYUTIL.getKey(clientCert.getPublicKey());
  let sigVerify = new KJUR.crypto.Signature({"alg": "SHA256withECDSA"});
  sigVerify.init(clientPublicKey);
  sigVerify.updateString(clientCertText);
  let isClientSigned = sigVerify.verify(clientSignatureHex); // Returns true if valid
  let CACertText = ""; 
  try {
    CACertText = readFileSync(process.env.SSL_CA_PEM_PATH).toString();
  } catch (error) {
    return res.json({isError: true, msg: "Failed to read CA cert", err: error.toString()});
  }
  let CAPublicKey = KEYUTIL.getKey(CACertText);
  let CACert = new X509();
  CACert.readCertPEM(CACertText);
  let isCAIssued = CACert.verifySignature(CAPublicKey);
  if (isCAIssued === true && isClientSigned === true) {
    let clientCertData = extractCertData(clientCert);
    if (clientCertData.isError === true) {
      console.log("Error extracting data from client cert", clientCertData.err);
      return res.json({isError: true, msg: "Error extracting data from client cert"});
    }
    clientCertData.createdIP = req.ip.replace("::ffff:", "");
    clientCertData.created = new Date();
    clientCertData.createdTimestamp = `${clientCertData.created.toLocaleDateString()} ${clientCertData.created.toLocaleTimeString().replace(/:\d{2} /g, "")}`;
    clientCertData.logs = [req.body.eventId];
    clientCertData.pemCert = clientCertText;
    let clientCertRegRes = registerCert(clientCertData);
    return res.json({isError: false, msg: "Certificate is valid and will be registered."});
  }
  return res.json({isError: false, msg: "Invalid certificate"});
};
module.exports = e;

