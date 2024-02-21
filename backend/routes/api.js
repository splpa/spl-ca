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
  let eventId = randomUUID();
  let ip = req.ip.replace("::ffff:", "");
  console.log(`${eventId}: Register request from ${ip}`);
  if ( !req.body.pemCertText ){
    console.log(`${eventId}: Register request missing pemCertText.`);
    return res.json({isError: true, msg: "Missing pemCertText property."});
  }
  let pemCertText = req.body.pemCertText;
  if ( !req.body.hexSignature ) {
    console.log(`${eventId}: Register request missing hexSignature.`);
    return res.json({isError: true, msg: "Missing hexSignature body property."});
  }
  let hexSignature = req.body.hexSignature;
  if ( !/^[a-f0-9]+$/i.test(hexSignature) ) {
    console.log(`${eventId}: Register request invalid hexSignature characters '${hexSignature}'.`);
    return res.json({isError: true, msg: "hexSignature contains invalid characters."});
  }
  register( pemCertText, hexSignature, ip, res, eventId );
});

module.exports = router;
