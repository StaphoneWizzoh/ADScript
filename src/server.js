const ldap = require("ldapjs");
const sqlite3 = require("sqlite3");
const crypto = require("crypto");
const path = require("path");
const config = require("../config/config");

// Production env
// const TLSManager = require("./security/tls");
const AuthProvider = require("./auth/authProvider");
// const GroupPolicy = require("./policy/gpo");
// const ReplicationManager = require("./replication/sync");
// const BackupManager = require("./backup/manager");
// const logger = require("./logger");

class ADServer {
    constructor(options = {}) {
        this.options = {
            host: options.host || "localhost",
            port: options.port || 3389,
            baseDN: options.baseDN || "dc=domain,dc=com",
            dbPath: options.dbPath || path.join(__dirname, "../ad_data.sqlite"),
        };
        this.db = new sqlite3.Database(this.options.dbPath);
        this.initDatabase();
        this.server = ldap.createServer();
        this.setupLDAPHandlers();
        this.groupService = new GroupService(this);
        this.authProvider = new AuthProvider({
            kerberos: options.auth?.kerberos,
        });
        // this.setupAdvancedFeatures(options);
    }

    // setupAdvancedFeatures(options) {
    //     this.tls = new TLSManager(options.certPath, options.keyPath);
    //     this.kerberos = new KerberosAuth(options.realm, options.kdc);
    //     this.gpo = new GroupPolicy(this.db);
    //     this.replication = new ReplicationManager(this, options.secondaries);
    //     this.backup = new BackupManager(this.db, options.backupPath);
    // }

    initDatabase() {
        const schema = `
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        sAMAccountName TEXT UNIQUE,
        userPrincipalName TEXT UNIQUE,
        distinguishedName TEXT UNIQUE,
        passwordHash TEXT,
        userAccountControl INTEGER,
        whenCreated TEXT,
        pwdLastSet TEXT
      );

      CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY,
        cn TEXT UNIQUE,
        distinguishedName TEXT UNIQUE,
        description TEXT
      );

      CREATE TABLE IF NOT EXISTS group_memberships (
        groupId INTEGER,
        userId INTEGER,
        FOREIGN KEY(groupId) REFERENCES groups(id),
        FOREIGN KEY(userId) REFERENCES users(id)
      );
        `;
        this.db.exec(schema);
    }

    setupLDAPHandlers() {
        this.server.bind(this.options.baseDN, (req, res, next) => {
            try {
                const dnParts = req.dn.toString().split(",");
                const username = dnParts[0].split("=")[1];
                const password = req.credentials;

                // Get auth method from request or config
                const authMethod =
                    req.authMethod ||
                    this.options.auth?.defaultMethod ||
                    "basic";

                this.authProvider
                    .authenticate(username, password, authMethod)
                    .then((authenticated) => {
                        if (authenticated) {
                            res.end();
                        } else {
                            next(new ldap.InvalidCredentialsError());
                        }
                    })
                    .catch((err) =>
                        next(new ldap.OperationsError(err.message))
                    );
            } catch (err) {
                next(new ldap.OperationsError(err.message));
            }
        });
        // ... rest of handlers
    }

    async authenticateUser(username, password) {
        return new Promise((resolve, reject) => {
            this.db.get(
                "SELECT passwordHash FROM users WHERE userPrincipalName = ? OR sAMAccountName = ?",
                [username, username],
                (err, row) => {
                    if (err) return reject(err);
                    if (!row) return resolve(false);

                    const hash = this.hashPassword(password);
                    resolve(hash === row.passwordHash);
                }
            );
        });
    }

    hashPassword(password) {
        // Use SHA-256
        return crypto.createHash("sha256").update(password).digest("hex");
    }

    async addUser({ sAMAccountName, userPrincipalName, password }) {
        const hash = this.hashPassword(password);
        const distinguishedName = `cn=${sAMAccountName},${this.options.baseDN}`;

        return new Promise((resolve, reject) => {
            this.db.run(
                `INSERT INTO users (sAMAccountName, userPrincipalName, distinguishedName, passwordHash) 
                 VALUES (?, ?, ?, ?)`,
                [sAMAccountName, userPrincipalName, distinguishedName, hash],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }

    async addGroup({ cn, description }) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `INSERT INTO groups (cn, description) 
                 VALUES (?, ?)`,
                [cn, description],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }

    start() {
        this.server.listen(this.options.port, this.options.host, () => {
            console.log(
                `AD server listening at http://${this.options.host}:${this.options.port}`
            );
        });
    }

    stop() {
        return new Promise((resolve, reject) => {
            this.server.close(() => {
                this.db.close((err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        });
    }
}

// Services
class GroupService {
    constructor(adServer) {
        this.db = adServer.db;
    }

    isUserMemberOf(username, groupName) {
        return new Promise((resolve, reject) => {
            this.db.get(
                `SELECT COUNT(*) as count FROM users u
                 JOIN group_memberships gm ON u.id = gm.userId
                 JOIN groups g ON gm.groupId = g.id
                 WHERE (u.sAMAccountName = ? OR u.userPrincipalName = ?)
                 AND g.cn = ?`,
                [username, username, groupName],
                (err, row) => {
                    if (err) return reject(err);
                    resolve(row.count > 0);
                }
            );
        });
    }

    addUserToGroup(username, groupName) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `INSERT INTO group_memberships (userId, groupId)
                 SELECT u.id, g.id
                 FROM users u, groups g
                 WHERE (u.sAMAccountName = ? OR u.userPrincipalName = ?)
                 AND g.cn = ?`,
                [username, username, groupName],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }
}

module.exports = {
    ADServer,
    GroupService,
};

if (require.main === module) {
    const server = new ADServer({
        host: config.server.host,
        port: config.server.port,
        baseDN: config.server.baseDN,
        auth: config.auth,
    });

    server.start();
}
