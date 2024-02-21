const Database = require('better-sqlite3');
const db = new Database(process.env.DB_PATH, { /*verbose: console.log*/ });
const { randomUUID } = require('crypto');
const recordProps = [
  { key: "publicKey", slType: "TEXT PRIMARY KEY", jsType: "string"},
  { key: "active", slType: "TEXT", jsType: "bool"},
  { key: "pending", slType: "TEXT", jsType: "bool"},
  { key: "pemCert", slType: "TEXT", jsType: "string"},
  { key: "created", slType: "INTEGER", jsType: "date"},
  { key: "createdTimestamp", slType: "TEXT", jsType: "dateStr"},
  { key: "requestID", slType: "INTEGER", jsType: "number"},
  { key: "createdIP", slType: "TEXT", jsType: "string"},
  { key: "updateIP", slType: "TEXT", jsType: "bool"},
  { key: "subjectStr", slType: "TEXT", jsType: "string"},
  { key: "updateSubjectStr", slType: "TEXT", jsType: "bool"},
  { key: "altNames", slType: "TEXT", jsType: "string"},
  { key: "updateAltNames", slType: "TEXT", jsType: "bool"},
  { key: "approveAll", slType: "TEXT", jsType: "bool"},
  { key: "logs", slType: "TEXT", jsType: "arrStr"}
];
const ITLogsProps = [
  { key: "id", slType: "TEXT PRIMARY KEY", jsType: "string"},
  { key: "text", slType: "TEXT", jsType: "string"},
  { key: "sentTo", slType: "TEXT", jsType: "string"},
  { key: "successful", slType: "TEXT", jsType: "bool"},
  { key: "sentDate", slType: "INTEGER", jsType: "date"},
  { key: "sentDateStr", slType: "TEXT", jsType: "dateStr"},
];
let recordPropsObj = {};
recordProps.map(p => recordPropsObj[p.key] = p.jsType);
let castToDB = (val, type) => {
  //cast from js to db
  switch (type) {
    case "bool":{
      return val === true ? "true" : "false";
    }
    case "date":{
      return val-0;
    }
    case "arrStr":{
      return val.join(";");
    }
    case "string":
    case "dateStr":{
      return val;
    }
    case "number":{
      return val-0;
    }
  }
};
let castFromDB = (val, type) => {
  //cast from db to js
  switch (type) {
    case "bool":{
      return val === "true" ? true : false;
    }
    case "date":{
      return new Date(val);
    }
    case "arrStr":{
      return val.split(";");
    }
    case "number":{
      return Number(val);
    }
    case "string":
    case "dateStr":{
      return val;
    }
  }
};
let e = {};
initalizeDBs = async () => {
  const CertificatesInfoExists = await db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name='CertificatesInfo';`).get();
  if (!CertificatesInfoExists) {
    console.log('Creating CertificatesInfo table');
    await db.prepare(`CREATE TABLE IF NOT EXISTS CertificatesInfo (${recordProps.map(p => `${p.key} ${p.slType}`).join(", ")});`).run();
  }
  const TextITLogsExists = await db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name='TextITLogs';`).get();
  if (!TextITLogsExists) {
    console.log('Creating TextITLogs table');
    await db.prepare(`CREATE TABLE IF NOT EXISTS IT_Text_Logs (${ITLogsProps.map(p => `${p.key} ${p.slType}`).join(", ")});`).run();
  }
}
initalizeDBs();

e.getRecord = async (publicKey, eventId) => {
  let res = await db.prepare('SELECT * FROM CertificatesInfo WHERE publicKey = ?').get(publicKey);
  let record = false;
  if ( res !== undefined ) {
    record = {};
    Object.keys(res).map( prop => record[prop] = castFromDB(res[prop], recordPropsObj[prop]) );
  }
  console.log(`${eventId}: ${record === false ? "Record not found for this key" : "Record found for this key" } '${publicKey}'.`);
  return record;
};

e.updateRecord = async (record, eventId) => {
  let mappedRecord = {};
  recordProps.forEach( p => mappedRecord[p.key] = castToDB(record[p.key], p.jsType) );
  const existingRecord = await db.prepare('SELECT * FROM CertificatesInfo WHERE publicKey = ?').get(mappedRecord.publicKey);
  if (existingRecord) {
    console.log(`${eventId}: Updating existing record for ${mappedRecord.publicKey}.`);
    return await db.prepare(`UPDATE CertificatesInfo SET ${recordProps.filter(p => p.key !== "publicKey").map(p => `${p.key} = ?`).join(", ")}, WHERE publicKey = ?`).run(...(recordProps.filter(p => p.key !== "publicKey").map(p => mappedRecord[p.key])));
  } else {
    console.log(`${eventId}: Creating new record for ${record.publicKey}.`);
    return await db.prepare(`INSERT INTO CertificatesInfo ( ${recordProps.map(p => p.key).join(", ")} ) VALUES ( ${recordProps.map(p => "?").join(", ")} )`).run(...recordProps.map(p => mappedRecord[p.key]));
  }
}

e.registerCert = async (certData, eventId) => {
  let alreadyExist = await db.prepare('SELECT * FROM CertificatesInfo WHERE publicKey = ?').get(certData.publicKey);
  if ( alreadyExist ) {
    return {isError: true, msg: "This certificate is already registered."};
  }
  let created = new Date();
  let newRecord = { };
  recordProps.forEach(p => {
    if ( typeof certData[p.key] != "undefined" ) {
      newRecord[p.key] = certData[p.key];
    }else {
      switch (p.jsType) {
        case "bool":{
          newRecord[p.key] = false;
          break;
        }
        case "date":{
          newRecord[p.key] = created;
          break;
        }
        case "dateStr":{
          newRecord[p.key] = `${created.toLocaleDateString()} ${created.toLocaleTimeString().replace(/:\d{2} /g, "")}`;
        }
        case "number":{
          newRecord[p.key] = 0;
          break;
        }
        default:{
          newRecord[p.key] = "";
        }
      }
    }
  });
  try {
    let addRes = await e.updateRecord(newRecord, eventId);
    return {isError: false, msg: "Certificate registered successfully.", data: addRes};
  } catch (error) {
    return {isError: true, msg: "Could not register certificate.", err: error.toString()};
  }
};
e.addTextLog = async (entry) => {
  entry.id = randomUUID();
  let castedEntry = {};
  entry.sentDate = new Date();
  entry.sentDateStr = `${new Date(entry.sentDate).toLocaleDateString()} ${new Date(entry.sentDate).toLocaleTimeString().replace(/:\d{2} /g, "")}`;
  ITLogsProps.forEach( p => castedEntry[p.key] = castToDB(entry[p.key], p.jsType) );
  return await db.prepare(`INSERT INTO IT_Text_Logs ( ${ITLogsProps.map(p => p.key).join(", ")} ) VALUES ( ${ITLogsProps.map(p => "?").join(", ")} )`).run(...ITLogsProps.map(p => castedEntry[p.key]));
};
module.exports = e;