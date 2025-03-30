const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const moment = require('moment');
const pool = require('./db');

const backupDir = path.join(__dirname, 'backups');
if (!fs.existsSync(backupDir)) {
  fs.mkdirSync(backupDir);
}

async function backupDatabase() {
  const date = moment().format('YYYY-MM-DD_HH-mm-ss');
  const backupFile = path.join(backupDir, `backup_${date}.sql`);

  const command = `mysqldump -u ${process.env.DB_USER} -p${process.env.DB_PASS} ${process.env.DB_NAME} > ${backupFile}`;

  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error('Backup failed:', error);
        reject(error);
        return;
      }
      console.log(`Backup created: ${backupFile}`);
      resolve(backupFile);
    });
  });
}

// Run daily backup
backupDatabase()
  .then(() => process.exit(0))
  .catch(() => process.exit(1));