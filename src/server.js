const ldap = require("ldapjs");
const sqlite3 = require("sqlite3");
const crypto = require("crypto");
const path = require("path");

class ADServer {
    constructor(options = {}) {
        this.options = {
            host: options.host || "localhost",
            port: options.port || 389,
            baseDN: options.baseDN || "dc=domain,dc=com",
            dbPath: options.dbPath || path.join(__dirname, "ad_data.sqlite"),
        };
        this.db = new sqlite3.Database(this.options.dbPath);
        this.initDatabase();
        this.server = ldap.createServer();
        this.setupLDAPHandlers();
    }

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
        // LDAP Bind Operation
        this.server.bind(this.options.baseDN, (req, res, next) => {
            const username = req.dn.toString();
            const password = req.credentials;

            this.authenticateUser(username, password)
                .then((authenticated) => {
                    if (authenticated) {
                        res.end();
                    } else {
                        return next(new ldap.InvalidCredentialsError());
                    }
                })
                .catch((err) => next(new ldap.OperationsError(err.message)));
        });

        // LDAP Search Operation
        this.server.search(this.options.baseDN, (req, res, next) => {
            const filter = req.filter.toString();
            const searchOptions = {
                scope: req.scope,
                filter: filter,
                attributes: req.attributes,
            };

            this.searchDirectory(searchOptions)
                .then((entries) => {
                    entries.forEach((entry) => res.send(entry));
                    res.end();
                })
                .catch((err) => next(new ldap.OperationsError(err.message)));
        });
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
        // Using NTLM-compatible hashing
        return crypto
            .createHash("md4")
            .update(Buffer.from(password, "utf16le"))
            .digest("hex");
    }

    start() {
        this.server.listen(this.options.port, this.options.host, () => {
            console.log(
                `AD server listening at ${this.options.host}:${this.options.port}`
            );
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
}

// Usage
const server = new ADServer({
    host: "localhost",
    port: 389,
    baseDN: "dc=mycompany,dc=com",
});

server.start;
