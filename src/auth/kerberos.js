const crypto = require("crypto");
const { kerberos } = require("kerberos");

class KerberosError extends Error {
    constructor(message, code) {
        super(message);
        this.code = code;
    }
}

class KerberosAuth {
    constructor(realm, kdc) {
        this.realm = realm;
        this.kdc = kdc;
        this.tickets = new Map();
        this.sessionKeys = new Map();
        this.delegationCache = new Map();
        this.preAuthKeys = new Map();
    }

    async authenticate(username, password, options = {}) {
        try {
            // Step 1: Pre-authentication
            const preAuthData = await this._performPreAuth(username, password);

            // Step 2: AS Exchange with pre-auth data
            const tgt = await this._requestTGT(username, password, preAuthData);

            // Step 3: TGS Exchange
            const serviceTicket = await this._requestServiceTicket(
                username,
                tgt,
                {
                    delegation: options.allowDelegation,
                    forwardable: options.allowForwarding,
                }
            );

            // Step 4: Client/Server Authentication
            return await this._validateServiceTicket(username, serviceTicket);
        } catch (err) {
            console.error("Kerberos authentication failed:", err);
            return false;
        }
    }

    async _performPreAuth(username, password) {
        // Generate pre-auth timestamp
        const timestamp = new Date();

        // Create pre-auth encryption key
        const preAuthKey = crypto
            .createHash("sha256")
            .update(password)
            .update(timestamp.toISOString())
            .digest();

        // Store for validation
        this.preAuthKeys.set(username, {
            key: preAuthKey,
            timestamp,
            expires: new Date(timestamp.getTime() + 2 * 60 * 1000), // 2 min validity
        });

        return {
            timestamp,
            encryptedTimestamp: this._encrypt(
                timestamp.toISOString(),
                preAuthKey
            ),
        };
    }

    async _requestTGT(username, password, preAuthData) {
        // Validate pre-auth data
        const storedPreAuth = this.preAuthKeys.get(username);
        if (!storedPreAuth || storedPreAuth.expires < new Date()) {
            throw new KerberosError(
                "Pre-authentication failed or expired",
                "KRB_AP_ERR_PREAUTH_FAILED"
            );
        }

        // Create AS-REQ with pre-auth data
        const asReq = {
            username,
            realm: this.realm,
            timestamp: new Date(),
            nonce: crypto.randomBytes(32).toString("hex"),
            preAuth: preAuthData,
        };

        // Generate session key and create TGT
        const sessionKey = crypto.randomBytes(32);
        this.sessionKeys.set(username, sessionKey);

        const tgt = {
            clientName: username,
            realm: this.realm,
            timestamp: asReq.timestamp,
            validity: 36000,
            sessionKey,
            flags: {
                forwardable: true,
                proxiable: true,
            },
        };

        this.tickets.set(username, {
            ticket: tgt,
            expires: new Date(Date.now() + tgt.validity * 1000),
        });

        return tgt;
    }

    async protocolTransition(sourceUser, targetUser, targetService) {
        // Verify source user has delegation rights
        if (!this._canDelegate(sourceUser)) {
            throw new KerberosError(
                "Protocol transition not allowed",
                "KRB_AP_ERR_DELEGATE_NOALLOWED"
            );
        }

        // Create S4U2Self request
        const s4u2self = {
            impersonator: sourceUser,
            target: targetUser,
            timestamp: new Date(),
        };

        // Generate transition ticket
        const transitionTicket = {
            clientName: targetUser,
            realm: this.realm,
            timestamp: s4u2self.timestamp,
            validity: 3600,
            serviceTarget: targetService,
            impersonator: sourceUser,
        };

        return transitionTicket;
    }

    async delegateCredentials(username, targetService, delegatedTicket) {
        // Verify ticket is delegatable
        if (!delegatedTicket.flags?.delegatable) {
            throw new KerberosError(
                "Ticket not delegatable",
                "KRB_AP_ERR_DELEGATE_NOALLOWED"
            );
        }

        // Store delegation info
        this.delegationCache.set(`${username}:${targetService}`, {
            ticket: delegatedTicket,
            expires: new Date(Date.now() + delegatedTicket.validity * 1000),
        });

        return true;
    }

    _canDelegate(username) {
        // Check if user has delegation rights (simplified)
        return username.endsWith("$") || username.startsWith("service_");
    }

    _encrypt(data, key) {
        const cipher = crypto.createCipheriv(
            "aes-256-cbc",
            key,
            crypto.randomBytes(16)
        );
        return Buffer.concat([cipher.update(data), cipher.final()]);
    }

    _decrypt(data, key) {
        const decipher = crypto.createDecipheriv(
            "aes-256-cbc",
            key,
            data.slice(0, 16)
        );
        return Buffer.concat([
            decipher.update(data.slice(16)),
            decipher.final(),
        ]);
    }

    // Regular cleanup
    _cleanup() {
        const now = new Date();

        for (const [key, data] of this.tickets.entries()) {
            if (data.expires < now) this.tickets.delete(key);
        }

        for (const [key, data] of this.preAuthKeys.entries()) {
            if (data.expires < now) this.preAuthKeys.delete(key);
        }

        for (const [key, data] of this.delegationCache.entries()) {
            if (data.expires < now) this.delegationCache.delete(key);
        }
    }
}

module.exports = KerberosAuth;
