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
    }

    async authenticate(username, password) {
        try {
            // Step 1: AS Exchange - Client requests TGT
            const tgt = await this._requestTGT(username, password);

            // Step 2: TGS Exchange - Use TGT to get service ticket
            const serviceTicket = await this._requestServiceTicket(
                username,
                tgt
            );

            // Step 3: Client/Server Authentication
            return await this._validateServiceTicket(username, serviceTicket);
        } catch (err) {
            console.error("Kerberos authentication failed:", err);
            return false;
        }
    }

    async _requestTGT(username, password) {
        // Create Authentication Service Request (AS-REQ)
        const asReq = {
            username,
            realm: this.realm,
            timestamp: new Date(),
            nonce: crypto.randomBytes(32).toString("hex"),
        };

        // Hash password using NT hash (same as Windows)
        const passwordHash = crypto
            .createHash("md4")
            .update(Buffer.from(password, "utf16le"))
            .digest();

        // Generate session key
        const sessionKey = crypto.randomBytes(32);
        this.sessionKeys.set(username, sessionKey);

        // Create TGT encrypted with KDC key (simulated)
        const tgt = {
            clientName: username,
            realm: this.realm,
            timestamp: asReq.timestamp,
            validity: 36000, // 10 hours
            sessionKey: sessionKey,
        };

        // Store TGT
        this.tickets.set(username, {
            ticket: tgt,
            expires: new Date(Date.now() + tgt.validity * 1000),
        });

        return tgt;
    }

    async _requestServiceTicket(username, tgt) {
        // Verify TGT is still valid
        const storedTicket = this.tickets.get(username);
        if (!storedTicket || storedTicket.expires < new Date()) {
            throw new KerberosError(
                "TGT expired or invalid",
                "KRB_AP_ERR_TKT_EXPIRED"
            );
        }

        // Create service ticket using session key
        const serviceTicket = {
            clientName: username,
            realm: this.realm,
            timestamp: new Date(),
            validity: 3600, // 1 hour
            sessionKey: this.sessionKeys.get(username),
        };

        return serviceTicket;
    }

    async _validateServiceTicket(username, serviceTicket) {
        // Verify ticket details
        if (
            serviceTicket.clientName !== username ||
            serviceTicket.realm !== this.realm ||
            serviceTicket.timestamp > new Date() ||
            !this.sessionKeys.get(username).equals(serviceTicket.sessionKey)
        ) {
            return false;
        }

        return true;
    }

    // Cleanup expired tickets periodically
    _cleanupTickets() {
        const now = new Date();
        for (const [username, ticket] of this.tickets.entries()) {
            if (ticket.expires < now) {
                this.tickets.delete(username);
                this.sessionKeys.delete(username);
            }
        }
    }
}

module.exports = KerberosAuth;
