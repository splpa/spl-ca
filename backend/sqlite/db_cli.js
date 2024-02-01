const Database = require('better-sqlite3');
const readline = require('readline');
const db = new Database('./backend/sqlite/records.db', { /*verbose: console.log*/ });
const validProps = ["publicKey","active","currentCert","created","createdTimestamp","requestID","createdIP","updateIP","subjectStr","updateSubjectStr","altNames","updateAltNames","approveAll"];
const pubKeyDisp = 20;
const displayProps = [{key:"publicKey", size: pubKeyDisp},{key:"active", size: 6},{key:"createdTimestamp", size: 18},{key:"requestID", size: 10},{key:"createdIP", size: 15},{key:"updateIP", size: 8},{key:"updateSubjectStr", size: 18},{key:"updateAltNames", size: 15},{key:"approveAll", size: 10}];
const updatibleProps = [ "active", "updateIP", "updateSubjectStr", "updateAltNames", "approveAll" ];
const itemSpace = "   ";
let listedKeys = [];
/*
  *key                  *type
  publicKey             TEXT PRIMARY KEY
  active                TEXT
  currentCert           TEXT
  created               INTEGER
  createdTimestamp      TEXT
  requestID             INTEGER
  createdIP             TEXT
  updateIP              TEXT
  subjectStr            TEXT
  updateSubjectStr      TEXT
  altNames              TEXT
  updateAltNames        TEXT
  approveAll            TEXT
*/
let readInput = async (prompt) => {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(prompt, (input) => {
      rl.close();
      resolve(input);
    });
  });
}
let getAll = async () => {
  return {isError: false, data: await db.prepare('SELECT * FROM CertificatesInfo').all() }
};
let exists = async (publicKey) => {
  return typeof await db.prepare('SELECT * FROM CertificatesInfo WHERE publicKey = ?').get(publicKey) == "undefined" ? false : true;
};
let getPending = async () => {
  return await getRecords("requestID", -1);
};
let getInactive = async () => {
  return await getRecords("active", "false");
}
let getRecords = async (prop, value) => {
  if ( !validProps.includes(prop) ) {
    return {isError:true, msg:`Invalid property name '${prop}'` , data:[]};
  }
  let res = await db.prepare(`SELECT * FROM CertificatesInfo WHERE ${prop} = ?`).all(value);
  return {isError: false, data: res };
};
let setRecord = async (publicKey, prop, value) => {
  if ( await exists( publicKey ) === true ) {
    return {data: await db.prepare(`UPDATE CertificatesInfo SET ${prop} = ? WHERE publicKey = ?`).run(value, publicKey)};
  }
  return {isError: true, msg: `Record for '${publicKey}' does not exists.`, data: []};
};
let allowApproveAll = async (publicKey) => {
  let res = await setRecord(publicKey, "approveAll", "true");
  if (res.data.changes === 1) return true;
  console.log(res);
  return false;
};
let display = ( records, prompt = false ) => {
  let i = 0;
  listedKeys = [];
  console.log( `${prompt === true ? `${"#".padStart(4, " ")} -   ` : ""}${displayProps.map( (prop) => prop.key.padEnd(prop.size, " ")).join(itemSpace)}` );
  console.log(records.map( (record) => {
    i = i + 1;
    listedKeys.push(record.publicKey);
    return `${prompt === true ? `${i.toString().padStart(4, " ")} -   ` : ""}${displayProps.map( (prop) => record[prop.key].toString().substring(0,prop.size).padEnd(prop.size, " ")).join(itemSpace)}`;
  }).join("\r\n"));
}
let mainMenu = () => {
  console.clear();
  console.log("-- Main Menu --");
  console.log("   1 - List pending requests");
  console.log("   2 - Update/Approve pending requests");
  console.log("   3 - List inactive requests");
  console.log("   4 - Set active/inactive record");
  console.log("   5 - List all records");
  console.log("   6 - Update any record");
  console.log("   7 - Exit");
}
( async ( ) => {
  while (true) {
    mainMenu();
    let userRes = await readInput("Enter your choice: ");
    if (userRes === "7" ) break;
    switch (userRes) {
      case "1":{
        console.clear();
        let pending = await getPending();
        if (pending.data.length === 0) {
          console.log("No pending requests.");
        } else {
          display(pending.data);
        }
        break;
      }
      case "2":{
        console.clear();
        let pending2 = await getPending();
        display(pending2.data, true);
        let userRes2 = await readInput("Enter # of request to edit: ");
        let num = parseInt(userRes2);
        if ( num > 0 && num <= pending2.data.length ) {
          if ( await allowApproveAll(listedKeys[num-1]) === true ) {
            console.log( await display(await getRecords("publicKey", listedKeys[num-1]).data) );
            console.log("Request Approved.");
          } else {
            console.log("Error approving request.");
          }
        } else {
          console.log("Invalid entry.");
        }
        break;
      }
      case "3":{
        console.clear();
        let inactive = await getInactive();
        if (inactive.data.length === 0) {
          console.log("No inactive requests.");
        } else {
          display(inactive.data);
        }
      break;
      }
      case "4":{
        console.clear();
        let all = await getAll();
        if (all.data.length === 0) {
          console.log("No records.");
        } else {
          display(all.data, true);
          let userRec = parseInt(await readInput("Enter # of record to activate/deactivate: "));
          if ( userRec >=1 && userRec <= all.data.length ) {
            let rec = all.data[userRec-1];
            let comfirm = (await readInput(`Do you want to ${all.data[userRec-1].active === "true" ? "deactivate" : "activate"} this publicKey "${rec.publicKey.substring(0,pubKeyDisp)}" (y/n)?: `)).toUpperCase().trim();
            if ( comfirm === "Y" ) {
              let newActive = rec.active === "true" ? "false" : "true";
              let res = await setRecord(rec.publicKey, "active", newActive);
              if ( res.data.changes === 1 ) {
                console.log(`Record ${newActive === "true" ? "activated" : "deactivated"}.`);
                display( (await getRecords("publicKey", rec.publicKey)).data );
              } else {
                console.log("Error updating record.");
              }
            } else  {
              console.log("Record not modified.");
            }
          } else {
            console.log("Invalid record entry.");
          }
        }
        break;
      }
      case "5":{
        console.clear();
        let all = await getAll();
        if (all.data.length === 0) {
          console.log("No records.");
        } else {
          display(all.data);
        }
        break;
      }
      case "6":{
        console.clear();
        let all2 = await getAll();
        if ( all2.data.length === 0 ) {
          console.log("No records.");
        } else {
          display(all2.data, true);
          let userRes3 = await readInput("Enter # of record to edit: ");
          let num2 = parseInt(userRes3);
          if ( num2 > 0 && num2 <= all2.data.length ) {
            console.log("Select property to update:");
            console.log("   # - "+"Property Name".padEnd(20," ")+"Current Value".padEnd(20," "));
            console.log( updatibleProps.map( (prop, i) => `${(i+1).toString().padStart(4," ")} - ${prop.padEnd(20, " ")}${all2.data[num2-1][prop].padEnd(20, " ")}` ).join("\r\n") );
            let userResProp = parseInt(await readInput("Enter your choice: "));
            if ( userResProp >= 1 && userResProp <= updatibleProps.length ) {
              let selProp = updatibleProps[userResProp-1];
              let currentVal = all2.data[num2-1][selProp];
              let newVal = currentVal === "true" ? "false": "true";
              console.log(`Do you want to change '${selProp}' from '${currentVal}' to '${newVal}' (y/n)?: `);
              let userResVal = (await readInput("Enter your choice: ")).toString().toUpperCase().trim();
              if ( userResVal == "Y" ) {
                if ( await setRecord(listedKeys[num2-1], selProp, newVal) === true ) {
                  console.log("Record updated.");
                } else {
                  console.log("Error updating record.");
                }
              } else {
                console.log("Record not updated.");
              }
            } else {
              console.log("Invalid property entry.");
            }
          } else {
            console.log("Invalid record entry.");
          }
        }
        break;
      }
      case "delete":{
        console.clear();
        let inactive = await getRecords("active", "false");
        if (inactive.data.length === 0) {
          console.log("No inactive records to delete.");
        } else {
          display( inactive.data, true );
          let userRes = await readInput( "Enter # of record to delete: " );
          let num = parseInt(userRes);
          if ( num > 0 && num <= inactive.data.length ) {
            let res = await db.prepare(`DELETE FROM CertificatesInfo WHERE publicKey = ?`).run(inactive.data[num-1].publicKey);
            if ( res.changes === 1 ) {
              console.log("Record deleted.");
            } else {
              console.log("Error deleting record.");
            }
          } else {
            console.log("Invalid entry.");
          }
        }
        break;
      }
      default:{
        console.log(`'${userRes}' is not a valid entry.`);
      }
    }
    await readInput("Press enter to continue...");
  }
})()