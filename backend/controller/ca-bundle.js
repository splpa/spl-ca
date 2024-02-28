const { get } = require('https');
const { readFileSync, writeFileSync, existsSync } = require('fs');
// URL of the certdata.txt file
const url = 'https://hg.mozilla.org/releases/mozilla-release/raw-file/default/security/nss/lib/ckfw/builtins/certdata.txt';
let pemCerts = null;
e = {};
// Function to download certdata.txt
let downloadCertData = (url) => {
  return new Promise((resolve, reject) => {
    let data = '';
    get(url, (res) => {
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', (err) => reject(err));
  });
}

// Function to convert certdata.txt to PEM format
let convertToPEM = (certdata) => {
  const certValuePattern = /(?<=CKA_VALUE MULTILINE_OCTAL\n)[^E]+/gm;
  let match;
  let pemCerts = [];
  let certs = 0;
  while ((match = certValuePattern.exec(certdata)) !== null) {
    let encodedCert = match[0].replace(/\n/g, "").substring(1).split("\\").map((octal) => parseInt(octal,8));
    let pemCert = `-----BEGIN CERTIFICATE-----\n${Buffer.from(encodedCert, 'binary').toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
    pemCerts.push(pemCert);
    certs++;
  }
  console.log(`Converted ${certs} certificates to PEM format`);
  return pemCerts.join('\n');
}

let FetchFirefoxCerts = async ()=>{
  try {
    const certdata = await downloadCertData(url);
    pemCerts = convertToPEM(certdata);
    writeFileSync( process.env.FIREFOX_PEM_BUNDLE_PATH, pemCerts);
    console.log('PEM certificates have been written to certificates.pem');
  } catch (error) {
    console.error('Error fetching firefox cert bundle:', error);
  }
};

e.updateBundle = async () => {
  let splrootcaPEM = "";
  try {
    splrootcaPEM = readFileSync(process.env.SSL_CA_PEM_PATH, 'utf8');
  } catch (error) {
    return console.error('Error reading ca pem file:', error);
  } 
  await FetchFirefoxCerts();
  if ( existsSync( process.env.FIREFOX_PEM_BUNDLE_PATH ) ) {
    if (pemCerts == null ) {
      try {
        pemCerts = readFileSync(process.env.FIREFOX_PEM_BUNDLE_PATH, 'utf8');
      } catch (error) {
        return console.error('Error reading firefox cert bundle:', error);
      }
    }
    try {
      writeFileSync(process.env.CA_PEM_BUNDLE_PATH, `${splrootcaPEM}\n${pemCerts}`);
    } catch (error) {
      return console.error('Error writing ca pem bundle:', error);
    }
  }
}
module.exports = e;