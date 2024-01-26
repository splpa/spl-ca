const { createHash } = require('crypto');
const { readFileSync, existsSync, writeFileSync } = require('fs');
const { KJUR } = require('jsrsasign');
const { spawn } = require('child_process');
const { updateRecord, getRecord } = require('../sqlite/db');
e = {};
e.validate = async (req, res, plainText, renewRequestId) => {
  if (KJUR.asn1.csr.CSRUtil.verifySignature( plainText ) !== true ) {
    console.log(`${renewRequestId}: CSR WAS TAMPERTED WITH. ${JSON.stringify(plainText)}`);
    //email alert
    return res.json({isError: true, msg: "THE CSR SENT HAS BEEN TAMPERED WITH!"});
  }
  let csr = KJUR.asn1.csr.CSRUtil.getParam( plainText );
  let csrInfo = new KJUR.asn1.csr.CertificationRequest(csr);
  let sourceIP = req.ip;
  let publicKey = csrInfo.params.sbjpubkey;
  let subjectStr = csrInfo.params.subject.str;
  let altNameIndx = csrInfo.params.extreq.map( e => {return e.extname;}).indexOf("subjectAltName");
  let altNames = csrInfo.params.extreq[altNameIndx].array.map( e => {return `${e.dns?`DNS: ${e.dns}`: `IP: ${e.ip}`}`}).join(", ");
  let publicKeyHash = createHash('sha256').update(publicKey).digest('hex');
  let match = await getRecord( publicKeyHash, renewRequestId);
  if ( match ) {
    if ( match.createdIP !== sourceIP && match.updateIP !== true && match.approveAll !== true ) {
      console.log(`${renewRequestId}: CSR was created from a different IP.`);
      return res.json({isError: true, msg: "CSR was created from a different IP. Have admin approve new IP then try again."});
    }
    let subjectStrHash = createHash('sha256').update(subjectStr).digest('hex');
    if ( match.subjectStr !== subjectStrHash && match.updateSubjectStr !== true && match.approveAll !== true ) {
      console.log(`${renewRequestId}: CSR subject does not match approved subject for this key.`);
      return res.json({isError: true, msg: "CSR subject does not match approved subject for this key. Revert to previous configuration or have admin approve new subjectStr then try again."});
    }
    let altNamesHash = createHash('sha256').update(altNames).digest('hex');
    if ( match.altNames !== altNamesHash && match.updateAltNames !== true && match.approveAll !== true ) {
      console.log(`${renewRequestId}: CSR altNames does not match approved altNames for this key.`);
      return res.json({isError: true, msg: "CSR altNames does not match approved altNames for this key. Revert to previous configuration or have admin approve new altNames then try again."})
    }
    match.approveAll = false;
    match.updateAltNames = false;
    match.updateSubjectStr = false;
    match.updateIP = false;
    
    console.log("CSR is valid and approved to continue.");
    await validCSR(res, plainText, renewRequestId);
  }
  } else {
    let created = new Date();
    let newRecord = {
      publicKeyHash: publicKeyHash,
      created: created - 0,
      createdISO: created.toISOString(),
      requestID: 0,
      createdIP: sourceIP,
      updateIP: false,
      subjectStr: "",
      updateSubjectStr: false,
      altNames: "",
      updateAltNames: false,
      approveAll: false,
      logs:[]
    };
    console.log(`${renewRequestId}:`,await updateRecord(newRecord, renewRequestId) );
    return res.json({isError: true, msg: "Key is not in approved list. Have admin approve the new key."});
  }
}

let validCSR = async (res, plainText, renewRequestId) => {
  
}
module.exports = e;