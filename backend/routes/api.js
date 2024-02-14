const { Router } = require('express');
const { renew, register, registerTest } = require('../controller/ca-tools');
const router = Router();
const { randomUUID } = require('crypto');

router.post('/renew', async (req, res) => {
  let eventId = randomUUID();
  console.log(`${eventId}: Renew request from ${req.ip.replace("::ffff:", "")}`);
  if (!req.body.req){
    console.log("Renew request missing req...");
    return res.json({isError: true, msg: "Missing req..."})
  }
  let reqData = req.body.req.toString().trim();
  if ( reqData.length < 100 || reqData.length > 2000 ){
    console.log(`${eventId}: Renew request is of an invalid req length ${reqData.length}`);
    return res.json({isError: true, msg: "Invalid req length..."+reqData.length});
  }
  if ( !/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/.test(reqData) ) {
    console.log(`${eventId}: Renew request is not a valid base64 string.`);
    return res.json({isError: true, msg: "Invalid base64 string for req..."});
  }
  let csrText = Buffer.from(reqData, 'base64').toString('utf8');
  if ( csrText.startsWith("-----BEGIN CERTIFICATE REQUEST-----") && /-----END CERTIFICATE REQUEST-----(\n{0,1}|\r\n)$/.test(csrText) ) {
    return await renew(req, res, csrText, eventId);
  } 
  console.log(`${eventId}: Renew request is not in the right format.`);
  return res.json({isError: true, msg: "Invalid cert request..."});
});
router.post("/register", async (req, res) => {
  return await registerTest(req,res);
  let eventId = randomUUID();
  console.log(`${eventId}: Register request from ${req.ip.replace("::ffff:", "")}`);
  if (!req.body.b64Cert){
    console.log(`${eventId}: Register request missing b64Cert.`);
    return res.json({isError: true, msg: "Missing b64Cert property."})
  }
  if ( !req.body.b64Sig ) {
    console.log(`${eventId}: Register request missing b64Sig.`);
    return res.json({isError: true, msg: "Missing b64Sig body property."})
  }
  let b64Cert = req.body.b64Cert.toString().trim();
  if ( b64Cert.length < 100 || b64Cert.length > 10000 ){
    console.log(`${eventId}: Register request is of an invalid b64Cert length ${b64Cert.length}`);
    return res.json({isError: true, msg: "Invalid b64Cert length."});
  }
  if ( !/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/.test(b64Cert) ) {
    console.log(`${eventId}: Register request b64Cert is not a valid base64 string.`);
    return res.json({isError: true, msg: "Invalid base64 string for b64Cert."});
  }
  let b64Sig = req.body.b64Sig.toString().trim();
  if ( b64Sig.length < 100 || b64Sig.length > 10000 ){
    console.log(`${eventId}: Register request is of an invalid b64Sig length ${b64Sig.length}`);
    return res.json({isError: true, msg: "Invalid b64Sig length."});
  }
  if ( !/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/.test(b64Sig) ) {
    console.log(`${eventId}: Register request b64Sig is not a valid base64 string.`);
    return res.json({isError: true, msg: "Invalid base64 string for b64Sig."});
  }
  return await register(b64Cert, b64Sig, res, eventId);
});

module.exports = router;
