const initSqlJs = require('sql.js');
const fs = require('fs');
const DB_PATH = './crimewatch.db';

let _db = null;

async function getDb() {
  if (_db) return _db;
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    _db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    _db = new SQL.Database();
  }
  return _db;
}

function saveDb(db) {
  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
}

module.exports = { getDb, saveDb };
