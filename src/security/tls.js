const fs = require("fs");
const path = require("path");
const tls = require("tls");

class TLSManager {
    constructor(certPath, keyPath) {
        this.options = {
            cert: fs.readFileSync(certPath),
            key: fs.readFileSync(keyPath),
            requestCert: true,
            rejectUnauthorized: true,
        };
    }
}
