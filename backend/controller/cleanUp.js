const { existsSync, unlinkSync } = require('fs');
let e = {};
e.cleanUp = ( path, eventId) => {
  if (existsSync(path)) {
    try {
      unlinkSync(path);
    } catch (error) {
      console.log(` ${eventId}: Error deleting file ${path}. Error: ${error.toString()}`);
      return {isError: true, msg: `Error deleting file ${path}.`, err: error.toString()};
    }
    return {isError: false, msg: `File ${path} deleted.`};
  }
  return {isError: false, msg: `File ${path} didn't exist.`};
}
module.exports = e;