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
module.exports = e;