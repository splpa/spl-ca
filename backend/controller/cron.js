let cron = require('node-cron');
const { getExpiringRecords } = require('../sqlite/db');
const { textIT } = require('./textIT');
const cronStr = '30 10 * * 1-5';
let e = {};
e.start = () => {
  console.log("Starting cron job");
  cron.schedule(cronStr, async () => {
    console.log("Checking for expiring certificates.");
    const now = new Date().getTime();
    let expiringCerts = await getExpiringRecords();
    if ( expiringCerts === false ) {
      console.log("No certs expiring soon.");
    } else {
      const oneDay = 24*60*60*1000;
      console.log("Expiring certs: ", expiringCerts);
      expiringCerts.forEach( async (cert) => {
        let daysLeft = Math.round((cert.expires - now)/ oneDay)
        let msg = `Cert for ${cert.publicKey} expires in ${daysLeft} days.`;
        await textIT(msg);
      });
    }
  });
};
module.exports = e;