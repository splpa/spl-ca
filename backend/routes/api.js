const { Router } = require('express');
const { validate } = require('../controller/validate');
const router = Router();
const { randomUUID } = require('crypto');

router.post('/renew', async (req, res) => {
  let renewRequestId = randomUUID();
  console.log(`${renewRequestId}: Renew request from ${req.ip}`);
  if (!req.body.req){
    console.log("Renew request missing req...");
    return res.json({isError: true, msg: "Missing req..."})
  }
  let reqData = req.body.req.toString().trim();
  if ( reqData.length < 100 || reqData.length > 2000 ){
    console.log(`${renewRequestId}: Renew request is of an invalid req length ${reqData.length}`);
    return res.json({isError: true, msg: "Invalid req length..."+reqData.length});
  }
  if ( !/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/.test(reqData) ) {
    console.log(`${renewRequestId}: Renew request is not a valid base64 string.`);
    return res.json({isError: true, msg: "Invalid base64 string for req..."});
  }
  let plainText = Buffer.from(reqData, 'base64').toString('utf8');
  console.log(plainText)
  if ( plainText.startsWith("-----BEGIN CERTIFICATE REQUEST-----") && /-----END CERTIFICATE REQUEST-----(\n{0,1}|\r\n)$/.test(plainText) ) {
    return await validate(req, res, plainText, renewRequestId);
  } 
  console.log(`${renewRequestId}: Renew request is not in the right format.`);
  return res.json({isError: true, msg: "Invalid cert request..."});
});
module.exports = router;
