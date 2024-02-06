const { existsSync, unlinkSync } = require('fs');
let e = {};
e.cleanUp = ( path ) => {
  if (existsSync(path)) {
    try {
      unlinkSync(path);
    } catch (error) {
      return {isError: true, msg: `Error deleting file ${path}.`, err: error.toString()};
    }
    return {isError: false, msg: `File ${path} deleted.`};
  }
  return {isError: false, msg: `File ${path} didn't exist.`};
}
e.convertTimestamp = ( timestampX509 ) => {
  //expected format: YYYYMMDDHHMMSSZ or YYMMDDHHMMSSZ
  let timestamp = new Date();
  if ( /^\d{14}Z/i.test(timestampX509) === true ) {
    timestamp.setFullYear(timestampX509.substring(0, 4));
    timestampX509 = timestampX509.substring(4);
  } else if ( /^\d{12}Z/i.test(timestampX509) === true ) {
    timestamp.setFullYear("20"+timestampX509.substring(0,2));
    timestampX509 = timestampX509.substring(2);
  } else {
    return {isError: true, err: `Invalid timestamp format: ${timestampX509}`};
  }
  timestamp.setMonth(timestampX509.substring(0, 2)-1);
  timestamp.setDate(timestampX509.substring(2, 4));
  timestamp.setHours(timestampX509.substring(4, 6));
  timestamp.setMinutes(timestampX509.substring(6, 8));
  timestamp.setSeconds(timestampX509.substring(8, 10));
  return {isError: false, timestamp: timestamp};
};
module.exports = e;