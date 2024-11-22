const kerberos = require("kerberos");

class KerberosAuth {
    constructor(realm, kdc) {
        this.realm = realm;
        this.kdc = kdc;
    }

    async authenticate(username, password) {
        const client = new kerberos.KerberosClient();
        return client.initializeClient(`${username}@${this.realm}`);
    }
}
