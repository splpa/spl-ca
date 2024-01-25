const Database = require('better-sqlite3');
const db = new Database('approved.db', { verbose: console.log });
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
      approved INTEGER,
      logs TEXT
    );`).run();
  }
}
initalizeDB();

e.getApproved = async (publicKeyHash) => {
  let res = await db.prepare('SELECT * FROM approved WHERE publicKeyHash = ?').get(publicKeyHash);
  console.log(res);
  let approved = {};
  if ( res ) {
    approved = {
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
      "approved": res.approved === 1 ? true : false,// INTEGER,
      "logs": res.logs.split(";") // TEXT
    }
  }
  return approved;
};

e.updateApproved = async (approved) => {
  let converted = {
    "publicKeyHash": approved.publicKeyHash,  // TEXT PRIMARY KEY,
    "created": approved.created,  // INTEGER,
    "createdISO": approved.createdISO,  // TEXT,
    "requestID": approved.requestID,  // INTEGER,
    "createdIP": approved.createdIP,  // TEXT,
    "updateIP": approved.updateIP === true ? 1 : 0,  // INTEGER,
    "subjectStr": approved.subjectStr,  // TEXT,
    "updateSubjectStr": approved.updateSubjectStr === true ? 1 : 0,  // INTEGER,
    "altNames": approved.altNames,  // TEXT,
    "updateAltNames": approved.updateAltNames === true ? 1 : 0,  // INTEGER,
    "approved": approved.approved === true ? 1 : 0,  // INTEGER,
    "logs": approved.logs.join(";"),  // TEXT
  }
  
  const existingApproved = await db.prepare('SELECT * FROM approved WHERE publicKeyHash = ?').get(converted.publicKeyHash);
  if (existingApproved) {
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
      approved = ?,
      logs = ?
      WHERE publicKeyHash = ?`).run(
        converted.created,
        converted.createdISO,
        converted.requestID,
        converted.createdIP,
        converted.updateIP,
        converted.subjectStr,
        converted.updateSubjectStr,
        converted.altNames,
        converted.updateAltNames,
        converted.approved,
        converted.logs,
        converted.publicKeyHash
      );
  } else {
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
      approved,
      logs
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      converted.publicKeyHash,
      converted.created,
      converted.createdISO,
      converted.requestID,
      converted.createdIP,
      converted.updateIP,
      converted.subjectStr,
      converted.updateSubjectStr,
      converted.altNames,
      converted.updateAltNames,
      converted.approved,
      converted.logs
    );
  }
}