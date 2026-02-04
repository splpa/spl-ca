const { KJUR, X509, KEYUTIL } = require('jsrsasign');
const { updateRecord, getRecord, registerCert, CertProps, addCsrRequest, getCsrRequest } = require('../sqlite/db');
const { retrieveCert, submitCSR } = require('./spawn');
const { createHash } = require('crypto');
const { textIT } = require('./textIT');
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
  if ( record.requestId > 0 && record.pemCert !== "" ) {
    console.log(`${eventId}: Checking with CA for cert for requestId ${record.requestId} to verify cert expiration.`);
    //first check if cert already exists
    let certRes = await retrieveCert(record.requestId, createHash("sha256").update(record.publicKey).digest('hex'), eventId);
    if ( certRes.isError ){
      return { isValid:false, msg: certRes.msg }
    }
    certStr = Buffer.from(certRes.b64Cert, "base64");
  } else if ( record.pemCert !== "" ){
    certStr = record.pemCert;
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
    let certExtract = extractCertData(cert);
    if ( certExtract.isError === true ) {
      return {isValid:false, msg: certExtract.msg, err: certExtract.err};
    }
    let certAltNames = certExtract.altNames;//cert.getExtSubjectAltName().array.map( (e) => {return `${e.dns?`DNS: ${e.dns}`: `IP: ${e.ip}`}`}).join(", ");
    let certSubjectStr = certExtract.subjectStr;//cert.getSubjectString();
    let certPublicKey = certExtract.publicKey;//Buffer.from(cert.getSPKI(), "hex").toString('base64');
    let certDaysToExpire = certExtrat.certDaysToExpire;//Math.round(Math.abs( expires.getTime() - new Date().getTime()) / oneDay);
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
    if ( match.active === false ) {
      console.log(`${eventId}: CSR was rejected, admin has inactivate this key.`);
      return res.json({isError: true, msg: "CSR was rejected, admin has inactivate this key."});
    }
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
      if (csrRes.requestId) match.requestId = csrRes.requestId;
      markPending(match, eventId);
      console.log(`${eventId}: ${csrRes.msg} ${csrRes.err}` );
      return res.json({isError: true, msg: csrRes.msg});
    }
    let certExtract = extractCertData(Buffer.from(csrRes.b64Cert, "base64").toString());
    if ( certExtract.isError === true ) {
      console.log(`${eventId}: Error extracting data from new cert.`, certExtract.err);
      textIT(`Error extracting data from a cert for ${match.subjectStr}. Please fix, eventId: ${eventId}.`);
    } else {
      match.subjectStr = certExtract.subjectStr;
      match.altNames = certExtract.altNames;
      match.createdIP = sourceIP;
      match.pemCert = certExtract.pemCert;
      match.requestId = csrRes.requestId;
      match.expires = certExtract.expires;
    }
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
      pemCert: "",
      created: created,
      createdTimestamp: `${created.toLocaleDateString()} ${created.toLocaleTimeString().replace(/:\d{2} /g,"")}`,
      expires: created,
      requestId: -1,
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
e.register = async (clientCertText, clientSignatureHex, ip, res, eventId) => {
  let clientCert = new X509();
  try {
    clientCert.readCertPEM(clientCertText);
  } catch (error) {
    console.log(`${eventId}: Error parsing cert "${clientCertText.replace(/(\n|\r)/g,"")}"`, error.toString());
    return res.json({isError: true, msg: "Failed to parse cert", err: error.toString()});
  }
  let clientPublicKey = KEYUTIL.getKey(clientCert.getPublicKey());
  let sigVerify = new KJUR.crypto.Signature({"alg": "SHA256withECDSA"});
  sigVerify.init(clientPublicKey);
  sigVerify.updateString(clientCertText);
  let isClientSigned = sigVerify.verify(clientSignatureHex); // Returns true if valid
  let CACertText = ""; 
  try {
    CACertText = readFileSync(process.env.SSL_CA_PEM_PATH).toString();
  } catch (error) {
    console.log(`${eventId}: Error reading CA cert`, error.toString());
    return res.json({isError: true, msg: "Failed to read CA cert"});
  }
  let CAPublicKey = KEYUTIL.getKey(CACertText);
  let CACert = new X509();
  CACert.readCertPEM(CACertText);
  let isCAIssued = CACert.verifySignature(CAPublicKey);
  if (isCAIssued === true && isClientSigned === true) {
    let clientCertData = extractCertData(clientCert);
    if (clientCertData.isError === true) {
      console.log(`${eventId}: Error extracting data from client cert`, clientCertData.err);
      return res.json({isError: true, msg: "Error extracting data from client cert"});
    }
    clientCertData.createdIP = ip;
    clientCertData.created = new Date();
    clientCertData.createdTimestamp = `${clientCertData.created.toLocaleDateString()} ${clientCertData.created.toLocaleTimeString().replace(/:\d{2} /g, "")}`;
    clientCertData.logs = [eventId];
    clientCertData.pemCert = clientCertText;
    let clientCertRegRes = await registerCert(clientCertData, eventId);
    if (clientCertRegRes.isError === true) {
      console.log(`${eventId}: ${clientCertRegRes.msg} ${typeof clientCertRegRes.err == 'undefined' ? "" : clientCertRegRes.err}`)
      return res.json({isError: true, msg: clientCertRegRes.msg});
    }
    textIT(`New certificate registered for ${clientCertData.subjectStr}. Please reivew.`);
    console.log(`${eventId}: Certificate was registered.`, clientCertRegRes);
    return res.json({isError: false, msg: "Certificate was registered."});
  }
  console.log(`${eventId}: Invalid certificate, isCAIssued: ${isCAIssued} isClientSigned: ${isClientSigned}.`);
  return res.json({isError: false, msg: "Invalid certificate"});
};
e.csrRequest = async (req, res, csrText, eventId) => {
  // Verify CSR signature
  if (KJUR.asn1.csr.CSRUtil.verifySignature(csrText) !== true) {
    console.log(`${eventId}: CSR signature verification failed.`);
    return res.json({ isError: true, msg: "CSR signature verification failed." });
  }
  // Extract public key from CSR
  let csr = KJUR.asn1.csr.CSRUtil.getParam(csrText);
  let csrInfo = new KJUR.asn1.csr.CertificationRequest(csr);
  let publicKey = csrInfo.params.sbjpubkey.replace(/(\r|\n|-+(BEGIN|END) PUBLIC KEY-+)/g, "");
  // Add to DB queue for PowerShell worker to process
  let addRes = await addCsrRequest(csrText, publicKey, eventId);
  if (addRes.isError === true) {
    console.log(`${eventId}: ${addRes.msg} ${addRes.err || ''}`);
    return res.json({ isError: true, msg: addRes.msg });
  }
  console.log(`${eventId}: CSR queued with uuid ${addRes.uuid}`);
  return res.json({ isError: false, msg: "CSR submitted successfully, pending processing.", uuid: addRes.uuid });
};

e.csrStatus = async (req, res, uuid, eventId) => {
  let record = await getCsrRequest(uuid);
  if (record === false) {
    console.log(`${eventId}: CSR request not found for uuid ${uuid}`);
    return res.json({ isError: true, msg: "Request not found." });
  }
  if (record.status === "issued" && record.b64Cert !== "") {
    // Auto-register the certificate if not already registered
    let certPem = Buffer.from(record.b64Cert, "base64").toString();
    let cert = new X509();
    try {
      cert.readCertPEM(certPem);
    } catch (error) {
      console.log(`${eventId}: Error parsing certificate: ${error.toString()}`);
      return res.json({ isError: false, status: "issued", msg: "Certificate issued.", b64Cert: record.b64Cert });
    }
    let certData = extractCertData(cert);
    if (certData.isError !== true) {
      let ip = req.ip.replace("::ffff:", "");
      certData.createdIP = ip;
      certData.created = new Date();
      certData.createdTimestamp = `${certData.created.toLocaleDateString()} ${certData.created.toLocaleTimeString().replace(/:\d{2} /g, "")}`;
      certData.logs = [eventId];
      certData.pemCert = certPem;
      certData.requestId = record.requestId;
      let registerRes = await registerCert(certData, eventId);
      if (registerRes.isError !== true) {
        textIT(`Certificate request ${record.uuid} was issued and auto-registered for ${certData.subjectStr}. Please review.`);
        console.log(`${eventId}: Certificate auto-registered for uuid ${uuid}`);
      }
    }
    return res.json({ isError: false, status: "issued", msg: "Certificate has been issued.", b64Cert: record.b64Cert });
  }
  if (record.status === "denied") {
    return res.json({ isError: false, status: "denied", msg: "Certificate request was denied." });
  }
  if (record.status === "failed") {
    return res.json({ isError: false, status: "failed", msg: "Certificate request failed.", error: record.error });
  }
  // pending_submit or submitted
  let statusMsg = record.status === "pending_submit" ? "Request is queued for submission." : "Certificate request is pending admin approval.";
  console.log(`${eventId}: Request ${uuid} status: ${record.status}`);
  return res.json({ isError: false, status: record.status, msg: statusMsg });
};

module.exports = e;