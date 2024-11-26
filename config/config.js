const config = {
    server: {
        host: process.env.AD_HOST || "localhost",
        port: parseInt(process.env.AD_PORT) || 3389,
        baseDN: process.env.AD_BASE_DN || "dc=mycompany,dc=com",
    },
    ldap: {
        timeout: parseInt(process.env.LDAP_TIMEOUT) || 30000,
        maxPageSize: parseInt(process.env.LDAP_MAX_PAGE_SIZE) || 1000,
    },
    auth: {
        defaultMethod: "basic",
        kerberos: {
            enabled: true,
            realm: process.env.KRB5_REALM || "DOMAIN.COM",
            kdc: process.env.KRB5_KDC || "kdc.domain.com",
        },
    },
};

module.exports = config;
