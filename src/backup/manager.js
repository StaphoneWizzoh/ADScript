class BackupManager {
    constructor(db, backupPath) {
        this.db = db;
        this.backupPath = backupPath;
    }

    async backup() {
        const timestamp = new Date().toISOString();
        const backupFile = path.join(
            this.backupPath,
            `backup-${timestamp}.sqlite`
        );
        return new Promise((resolve, reject) => {
            this.db.backup(backupFile, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }
}
