const { addTextLog } = require('../sqlite/db');

const e = {
  textIT: async (msg) => {
    msg = `${process.env.SERVICE_NAME.toUpperCase()}:\n${msg}`;
    let logEntry = {
      text: msg,
      sentTo: process.env.IT_EMAIL,
      successful: false
    };
    if (!process.env.SMTP2GO_API_KEY) {
      console.log(`SMTP2GO_API_KEY not configured, "${msg}" not sent.`);
      await addTextLog(logEntry);
      return false;
    }
    console.log(`Emailing IT: "${msg}"`);
    let mailRes = {};
    try {
      const response = await fetch('https://api.smtp2go.com/v3/email/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          api_key: process.env.SMTP2GO_API_KEY,
          to: [process.env.IT_EMAIL],
          sender: process.env.SMTP2GO_FROM,
          subject: `${process.env.SERVICE_NAME.toUpperCase()} - Certificate Alert`,
          text_body: msg
        })
      });
      mailRes = await response.json();
    } catch (error) {
      mailRes = { isError: true, err: error.toString() };
    }
    if (mailRes.isError === true || mailRes.data?.failed > 0) {
      console.log(`Email failed: ${JSON.stringify(mailRes)}`);
      await addTextLog(logEntry);
      return false;
    } else {
      logEntry.successful = true;
      await addTextLog(logEntry);
      console.log(`Email Sent: ${mailRes.data?.email_id || 'success'}`);
    }
    return true;
  }
};

module.exports = e;
