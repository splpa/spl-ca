let cron = require('node-cron');
const { existsSync } = require('fs');
const { getExpiringRecords } = require('../sqlite/db');
const { updateBundle } = require('./ca-bundle');
const { textIT } = require('./textIT');
const cronDailyStr = '30 10 * * 1-5';
const cronAnnuallyStr = '45 10 5 2 *';
let dailyCertCheck = null;
let annualCABundleUpdate = null;
let e = {};
e.start = async () => {
  dailyCertCheck = cron.schedule(cronDailyStr, async () => {
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
  },{
    scheduled: true
  });
  console.log(`Added cron job for daily cert check`);
  annualCABundleUpdate = cron.schedule(cronAnnuallyStr, async () => {
    console.log("Updating CA bundle.");
    await updateBundle();
  },{
    scheduled: true
  });
  console.log(`Adding cron job for annual CA bundle update`);
  if ( !existsSync(process.env.CA_PEM_BUNDLE_PATH) ) {
    console.log("CA bundle does not exist. Creating bundle.");
    await updateBundle();
  }
};
module.exports = e;