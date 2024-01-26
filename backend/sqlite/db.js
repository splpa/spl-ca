const Database = require('better-sqlite3');
const db = new Database('approved.db', { /*verbose: console.log*/ });
let e = {};
initalizeDB = async () => {
  const tableExists = await db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name='approved';`).get();
  if (!tableExists) {
    console.log('Creating approved table');
    await db.prepare(`CREATE TABLE IF NOT EXISTS approved (
      publicKeyHash TEXT PRIMARY KEY,
      created INTEGER,
      createdISO TEXT,
      requestID INTEGER,
      createdIP TEXT,
      updateIP INTEGER,
      subjectStr TEXT,
      updateSubjectStr INTEGER,
      altNames TEXT,
      updateAltNames INTEGER,
      approveAll INTEGER,
      logs TEXT
    );`).run();
  }
}
initalizeDB();

e.getRecord = async (publicKeyHash, renewRequestId) => {
  let res = await db.prepare('SELECT * FROM approved WHERE publicKeyHash = ?').get(publicKeyHash);
  let record = false;
  if ( res !== undefined ) {
    record = {
      "publicKeyHash": res.publicKeyHash,// TEXT PRIMARY KEY,
      "created": res.created,// INTEGER,
      "createdISO": res.createdISO,// TEXT,
      "requestID": res.requestID,// INTEGER,
      "createdIP": res.createdIP,// TEXT,
      "updateIP": res.updateIP === 1 ? true : false,// INTEGER,
      "subjectStr": res.subjectStr,// TEXT,
      "updateSubjectStr": res.updateSubjectStr === 1 ? true : false,// INTEGER,
      "altNames": res.altNames,// TEXT,
      "updateAltNames": res.updateAltNames === 1 ? true : false,// INTEGER,
      "approveAll": res.approveAll === 1 ? true : false,// INTEGER,
      "logs": res.logs.split(";") // TEXT
    }
  }
  console.log(`${renewRequestId}: ${record === false ? "Record not found for this key" : "Record found for this key" } '${publicKeyHash}'.`);
  return record;
};

e.updateRecord = async (record, renewRequestId) => {
  let mappedRecord = {
    "publicKeyHash": record.publicKeyHash,  // TEXT PRIMARY KEY,
    "created": record.created,  // INTEGER,
    "createdISO": record.createdISO,  // TEXT,
    "requestID": record.requestID,  // INTEGER,
    "createdIP": record.createdIP,  // TEXT,
    "updateIP": record.updateIP === true ? 1 : 0,  // INTEGER,
    "subjectStr": record.subjectStr,  // TEXT,
    "updateSubjectStr": record.updateSubjectStr === true ? 1 : 0,  // INTEGER,
    "altNames": record.altNames,  // TEXT,
    "updateAltNames": record.updateAltNames === true ? 1 : 0,  // INTEGER,
    "approveAll": record.approveAll === true ? 1 : 0,  // INTEGER,
    "logs": record.logs.join(";"),  // TEXT
  }
  
  const existingRecord = await db.prepare('SELECT * FROM approved WHERE publicKeyHash = ?').get(mappedRecord.publicKeyHash);
  if (existingRecord) {
    console.log(`${renewRequestId}: Updating existing record for ${mappedRecord.publicKeyHash}.`);
    return await db.prepare(`UPDATE approved SET
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
      WHERE publicKeyHash = ?`).run(
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
        mappedRecord.publicKeyHash
      );
  } else {
    console.log(`${renewRequestId}: Creating new record for ${record.publicKeyHash}.`);
    return await db.prepare(`INSERT INTO approved (
      publicKeyHash,
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
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      mappedRecord.publicKeyHash,
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