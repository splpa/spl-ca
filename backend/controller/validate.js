const { readFileSync, existsSync, writeFileSync } = require('fs');
const { KJUR, X509 } = require('jsrsasign');
const { spawn } = require('child_process');
const { updateRecord, getRecord } = require('../sqlite/db');
const { join } = require('path');
e = {};
e.validate = async (req, res, csrText, eventId) => {
  if (KJUR.asn1.csr.CSRUtil.verifySignature( csrText ) !== true ) {
    console.log(`${eventId}: CSR WAS TAMPERTED WITH. ${JSON.stringify(csrText)}`);
    //email alert
    return res.json({isError: true, msg: "THE CSR SENT HAS BEEN TAMPERED WITH!"});
  }
  let csr = KJUR.asn1.csr.CSRUtil.getParam( csrText );
  let csrInfo = new KJUR.asn1.csr.CertificationRequest(csr);
  let sourceIP = req.ip;
  let publicKey = csrInfo.params.sbjpubkey.replace(/(\r|\n|-+(BEGIN|END) PUBLIC KEY-+)/g,"");
  let subjectStr = csrInfo.params.subject.str;
  let altNameIndx = csrInfo.params.extreq.map( e => {return e.extname;}).indexOf("subjectAltName");
  let altNames = csrInfo.params.extreq[altNameIndx].array.map( e => {return `${e.dns?`DNS: ${e.dns}`: `IP: ${e.ip}`}`}).join(", ");
  let match = await getRecord( publicKey, eventId);
  if ( match ) {
    if ( match.createdIP !== sourceIP && match.updateIP !== true && match.approveAll !== true ) {
      console.log(`${eventId}: CSR was created from a different IP.`);
      return res.json({isError: true, msg: "CSR was created from a different IP. Have admin approve new IP then try again."});
    }
    if ( match.subjectStr !== subjectStr && match.updateSubjectStr !== true && match.approveAll !== true ) {
      console.log(`${eventId}: CSR subject does not match approved subject for this key.`);
      return res.json({isError: true, msg: "CSR subject does not match approved subject for this key. Revert to previous configuration or have admin approve new subjectStr then try again."});
    }
    if ( match.altNames !== altNames && match.updateAltNames !== true && match.approveAll !== true ) {
      console.log(`${eventId}: CSR altNames does not match approved altNames for this key.`);
      return res.json({isError: true, msg: "CSR altNames does not match approved altNames for this key. Revert to previous configuration or have admin approve new altNames then try again."})
    }    
    console.log(`${eventId}: CSR is valid a format.`);
    await validCSR(res, match, csr, eventId);
  } else {
    let created = new Date();
    let newRecord = {
      publicKey: publicKey,
      currentCert: "",
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
    console.log(`${eventId}: New record added to DB. Requires admin approval.`, await updateRecord(newRecord, eventId) );
    return res.json({isError: true, msg: "Key is not in approved list. Have admin approve the new key."});
  }
}

let validCSR = async (res, record, csr, eventId) => {
  let certStr = null;
  let cert = null;
  if ( record.requestID > 0 && record.currentCert !== "" ) {
    console.log(`${eventId}: Checking with CA for cert for requestID ${record.requestID} to verify cert expiration.`);
    //first check if cert already exists
    if ( existsSync(join(certsRoot, `${record.publicKey}.crt`)) ) {
      try {
        certStr = readFileSync(join(certsRoot, `${record.publicKey}.crt`));
      } catch (error) {
        console.log(`${eventId}: Error reading cert for requestID ${record.requestID}, Error: ${error.toString()}.`);
      }
    } else {
      //code to get cert from CA
      //certreq -retrieve -config "SPLROOTCA\PathologyAssociates-SPLROOTCA-CA" 26 "C:\temp\test.crt"
      spawn("certreq", ["-retrieve", "-config", "SPLROOTCA\\PathologyAssociates-SPLROOTCA-CA", record.requestID, join(certsRoot, `${record.publicKey}.crt`)]);

    }
    if ( certStr !== null ) {
      cert = new X509();
      try {
        cert.readCertPEM(certStr); 
      } catch (error) {
        //code this.
      }
    }
  } else if (record.currentCert !== "" ){
    certStr = record.currentCert;
  } else {
    //no cert exist only continue if admin has approved this key
    if (record.approveAll !== true) {
      console.log(`${eventId}: Pending Admin approval for ${record.publicKey}.`);
      return res.json({isError: true, msg: "Admin approval is required to sign certificate."});
    }
  } 
  if ( record.approveAll === true ) {
    return await generateNewCert(res, record, eventId);
  } else {
    let certAltNames = cert.getExtSubjectAltName().array.map( (e) => {return `${e.dns?`DNS: ${e.dns}`: `IP: ${e.ip}`}`}).join(", ");
    let certSubjectStr = cert.getSubjectString();
    let certPublicKey = Buffer.from(cert.getSPKI(), "hex").toString('base64');
    if ( record.updateSubjectStr !== true ) {
       if ( record.subjectStr !== certSubjectStr ) {
        console.log(`${eventId}: CSR subject does not match Certficate subject for key: ${csr.publicKey}.`);
        return res.json({isError: true, msg: "CSR subject does not match Certficate subject for this key. Revert to previous configuration or have admin approve new subjectStr then try again."});
       }
    }
    if ( record.updateAltNames !== true ) {
      if ( record.altNames !== certAltNames ) {
        console.log(`${eventId}: CSR altNames does not match Certficate altNames for key: ${csr.publicKey}.`);
        return res.json({isError: true, msg: "CSR altNames does not match Certficate altNames for this key. Revert to previous configuration or have admin approve new altNames then try again."});
      }
    }
    if ( record.updatePublicKey !== true ) {
      if ( record.publicKey !== certPublicKey ) {
        console.log(`${eventId}: CSR publicKey does not match Certficate publicKey (${certPublicKey}) for key: ${csr.publicKey}.`);
        return res.json({isError: true, msg: "CSR publicKey does not match Certficate publicKey for this key. Revert to previous configuration or have admin approve new publicKey then try again."});
      }
    }
    return await generateNewCert(res, record, eventId);
  }
}
module.exports = e;



// if ( certStr !== null ) {
//   let cert = null;
//   try {
//     cert = new X509();
//     cert.readCertPEM(certStr);
//   } catch (error) {
//     console.log(`${eventId}: Error reading cert for requestID ${record.requestID}, Error: ${error.toString()}.`);
//     cleanUp(join(certsRoot, `${record.publicKey}.crt`));
//   }
// }
// let cert = readFileSync(record.currentCert);
// let certInfo = KJUR.asn1.x509.X509Util.getSubjectInfo(cert);
// let certExpiry = new Date(certInfo.notAfter);
// let now = new Date();
// if ( certExpiry < now ) {
//   console.log(`${eventId}: Cert for requestID ${record.requestID} has expired.`);
//   return res.json({isError: true, msg: "Cert for this requestID has expired. Please request a new cert."});
// }