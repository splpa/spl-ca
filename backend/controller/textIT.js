const { addTextLog } = require('../sqlite/db');
let client = {};
let twilioWorking = false;
try {
  client = require('twilio')(process.env.ACCOUNTSID, process.env.AUTH_TOKEN);
  twilioWorking = true;
} catch (error) {
  console.log(`Twilio client error: ${error.toString()}`);
}
const e = {
  textIT: async (msg) => {
    msg = `${process.env.SERVICE_NAME.toUpperCase()}:\n${msg}`;
    let logEntry = {
      text: msg,
      sentTo: process.env.IT_PHONE,
      successful: false
    };
    if (twilioWorking === false) {
      console.log(`Twilio client not working, "${msg}" not sent.`);
      await addTextLog(logEntry);
      return false;
    }
    console.log(`Texting IT: "${msg}"`);
    let twilioRes = {};
    try {
      twilioRes = await client.messages.create({
        body: msg,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: process.env.IT_PHONE
      });
    } catch (error) {
      twilioRes = {isError: true, err: error.toString()};
    }
    if (twilioRes.isError === true) {
      console.log( `Text failed: ${ JSON.stringify(twilioRes) }` );
    } else {
      logEntry.successful = true;
      await addTextLog(logEntry);
      console.log( `Text Sent: ${twilioRes.sid}` );
    }
    return true;
  }
};
 module.exports = e;