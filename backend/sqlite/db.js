const Database = require('better-sqlite3');
const db = new Database('approved.db', { /*verbose: console.log*/ });
let e = {};
initalizeDB = async () => {
  const tableExists = await db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name='approved';`).get();
  if (!tableExists) {
    console.log('Creating approved table');
    await db.prepare(`CREATE TABLE IF NOT EXISTS approved (
      publicKey TEXT PRIMARY KEY,
      active TEXT,
      currentCert TEXT,
      created INTEGER,
      createdISO TEXT,
      requestID INTEGER,
      createdIP TEXT,
      updateIP TEXT,
      subjectStr TEXT,
      updateSubjectStr TEXT,
      altNames TEXT,
      updateAltNames TEXT,
      approveAll TEXT,
      logs TEXT
    );`).run();
  }
}
initalizeDB();

e.getRecord = async (publicKey, eventId) => {
  let res = await db.prepare('SELECT * FROM approved WHERE publicKey = ?').get(publicKey);
  let record = false;
  if ( res !== undefined ) {
    record = {
      publicKey: res.publicKey,// TEXT PRIMARY KEY,
      active: res.active === "true" ? true : false,
      currentCert: res.currentCert,
      created: res.created,// INTEGER,
      createdISO: res.createdISO,// TEXT,
      requestID: res.requestID,// INTEGER,
      createdIP: res.createdIP,// TEXT,
      updateIP: res.updateIP === "true" ? true : false,// INTEGER,
      subjectStr: res.subjectStr,// TEXT,
      updateSubjectStr: res.updateSubjectStr === "true" ? true : false,// INTEGER,
      altNames: res.altNames,// TEXT,
      updateAltNames: res.updateAltNames === "true" ? true : false,// INTEGER,
      approveAll: res.approveAll === "true" ? true : false,// INTEGER,
      logs: res.logs.split(";") // TEXT
    }
  }
  console.log(`${eventId}: ${record === false ? "Record not found for this key" : "Record found for this key" } '${publicKey}'.`);
  return record;
};

e.updateRecord = async (record, eventId) => {
  let mappedRecord = {
    publicKey: record.publicKey,  // TEXT PRIMARY KEY,
    active: record.active === true ? "true" : "false",  // TEXT,
    currentCert: record.currentCert,  // TEXT,
    created: record.created,  // INTEGER,
    createdISO: record.createdISO,  // TEXT,
    requestID: record.requestID,  // INTEGER,
    createdIP: record.createdIP,  // TEXT,
    updateIP: record.updateIP === true ? "true" : "false",  // TEXT,
    subjectStr: record.subjectStr,  // TEXT,
    updateSubjectStr: record.updateSubjectStr === true ? "true" : "false",  // TEXT,
    altNames: record.altNames,  // TEXT,
    updateAltNames: record.updateAltNames === true ? "true" : "false",  // TEXT,
    approveAll: record.approveAll === true ? "true" : "false",  // TEXT,
    logs: record.logs.join(";"),  // TEXT
  }
  
  const existingRecord = await db.prepare('SELECT * FROM approved WHERE publicKey = ?').get(mappedRecord.publicKey);
  if (existingRecord) {
    console.log(`${eventId}: Updating existing record for ${mappedRecord.publicKey}.`);
    return await db.prepare(`UPDATE approved SET
      active = ?,
      currentCert = ?,
      created = ?,
      createdISO = ?,
      requestID = ?,
      createdIP = ?,
      updateIP = ?,
      subjectStr = ?,
      updateSubjectStr = ?,
      altNames = ?,
      updateAltNames = ?,
      approveAll = ?,
      logs = ?
      WHERE publicKey = ?`).run(
        mappedRecord.active,
        mappedRecord.currentCert,
        mappedRecord.created,
        mappedRecord.createdISO,
        mappedRecord.requestID,
        mappedRecord.createdIP,
        mappedRecord.updateIP,
        mappedRecord.subjectStr,
        mappedRecord.updateSubjectStr,
        mappedRecord.altNames,
        mappedRecord.updateAltNames,
        mappedRecord.approveAll,
        mappedRecord.logs,
        mappedRecord.publicKey
      );
  } else {
    console.log(`${eventId}: Creating new record for ${record.publicKey}.`);
    return await db.prepare(`INSERT INTO approved (
      publicKey,
      active,
      currentCert,
      created,
      createdISO,
      requestID,
      createdIP,
      updateIP,
      subjectStr,
      updateSubjectStr,
      altNames,
      updateAltNames,
      approveAll,
      logs
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      mappedRecord.publicKey,
      mappedRecord.active,
      mappedRecord.currentCert,
      mappedRecord.created,
      mappedRecord.createdISO,
      mappedRecord.requestID,
      mappedRecord.createdIP,
      mappedRecord.updateIP,
      mappedRecord.subjectStr,
      mappedRecord.updateSubjectStr,
      mappedRecord.altNames,
      mappedRecord.updateAltNames,
      mappedRecord.approveAll,
      mappedRecord.logs
    );
  }
}
module.exports = e;