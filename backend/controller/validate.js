const { createHash } = require('crypto');
const { readFileSync, existsSync, writeFileSync } = require('fs');
const { KJUR } = require('jsrsasign');
const { spawn } = require('child_process');
const { updateApproved, getApproved } = require('../sqlite/db');
e = {};
e.validate = async (req, res, plainText, renewRequestId) => {
  console.log("plainText:",plainText);
  let csr = new KJUR.asn1.csr.CertificationRequestInfo(plainText);
  let sourceIP = req.ip;
  console.log( JSON.stringify( csr, null, 2 ));
  let publicKey = csr.params.sbjpubkey;
  let subjectStr = csr.params.subject.str;
  let altNameIndx = csr.params.extreq.map( e => {return e.extname;}).indexOf("subjectAltName");
  let altNames = csr.params.extreq[altNameIndx].array.map( e => {return `${e.dns?`DNS: ${e.dns}`: `IP: ${e.ip}`}`}).join(", ");
  let publicKeyHash = createHash('sha256').update(publicKey).digest('hex');
  let match = await getApproved( publicKeyHash );
  if ( match ) {
    //key is in approved list verify subject and altName
    if ( match.createdIP !== sourceIP && match.updateIP !== true && match.approved !== true ) {
      return res.json({isError: true, msg: "CSR was created from a different IP. Have admin approve new IP then try again."});
    }
    let subjectStrHash = createHash('sha256').update(subjectStr).digest('hex');
    if ( match.subjectStr !== subjectStrHash && match.updateSubjectStr !== true && match.approved !== true ) {
      return res.json({isError: true, msg: "CSR subject does not match approved subject for this key. Revert to previous configuration or have admin approve new subjectStr then try again."});
    }
    let altNamesHash = createHash('sha256').update(altNames).digest('hex');
    if ( match.altNames !== altNamesHash && match.updateAltNames !== true && match.approved !== true ) {
      return res.json({isError: true, msg: "CSR altNames does not match approved altNames for this key. Revert to previous configuration or have admin approve new altNames then try again."})
    }
    console.log("CSR is valid and approved to continue.");
    match.approved = false;
    process.exit(1);
  } else {
    let created = new Date();
    match = {
      created: created - 0,
      createdISO: created.toISOString(),
      requestID: 0,
      createdIP: sourceIP,
      updateIP: false,
      subjectStr: "",
      updateSubjectStr: false,
      altNames: "",
      updateAltNames: false,
      approved: false,
      logs:[]
    };
    console.log( await updateApproved(match) );
    return res.json({isError: true, msg: "Key is not in approved list. Have admin approve the new key."});
  }
}

module.exports = e;