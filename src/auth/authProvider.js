const crypto = require("crypto");

class AuthProvider {
    constructor(options = {}, db) {
        this.db = db; // Add database reference
        this.authMethods = new Map();
        this.setupAuthMethods(options);
    }

    setupAuthMethods(options) {
        this.authMethods.set("basic", this.basicAuth.bind(this));

        if (options.kerberos?.enabled) {
            try {
                const KerberosAuth = require("./kerberos");
                const kerberosAuth = new KerberosAuth(
                    options.kerberos.realm,
                    options.kerberos.kdc
                );
                this.authMethods.set(
                    "kerberos",
                    kerberosAuth.authenticate.bind(kerberosAuth)
                );
            } catch (err) {
                console.warn("Kerberos auth not available:", err.message);
            }
        }
    }

    async authenticate(username, password, method = "basic") {
        const authMethod = this.authMethods.get(method);
        if (!authMethod) {
            throw new Error(`Auth method ${method} not supported`);
        }
        return authMethod(username, password);
    }

    async basicAuth(username, password) {
        return new Promise((resolve, reject) => {
            this.db.get(
                "SELECT passwordHash FROM users WHERE userPrincipalName = ? OR sAMAccountName = ?",
                [username, username],
                (err, row) => {
                    if (err) return reject(err);
                    if (!row) return resolve(false);
                    const hash = crypto
                        .createHash("sha256")
                        .update(password)
                        .digest("hex");
                    resolve(hash === row.passwordHash);
                }
            );
        });
    }
}

module.exports = AuthProvider;
