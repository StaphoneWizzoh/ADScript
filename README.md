# ADScript

**ADScript** is a lightweight Active Directory (AD) server implementation built with Node.js. It provides core AD functionalities, including user authentication, group management, and data replication.

---

## Features

-   **User Authentication:** Supports LDAP-based user authentication with SHA-256 password hashing.
-   **Group Management:** Manage group memberships and add users to groups seamlessly.
-   **Database Management:** Uses SQLite for efficient storage of user and group data.
-   **Backup Manager:** Create and manage database backups.
-   **Logging:** Integrates Winston for error tracking and combined logs.
-   **Testing:** Includes unit tests powered by Mocha for reliability.

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/StaphoneWizzoh/ADScript.git
cd ADScript
```

### 2. Install Dependencies

```bash
npm install
```

---

## Configuration

Edit the server settings in `config/config.js` as needed:

```js
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
};

module.exports = config;
```

### Environment Variables

You can override the default settings using the following environment variables:

-   `AD_HOST`
-   `AD_PORT`
-   `AD_BASE_DN`
-   `LDAP_TIMEOUT`
-   `LDAP_MAX_PAGE_SIZE`

---

## Usage

### Start the Server

```bash
npm start
```

The AD server will listen on the configured host and port.

---

## Testing

Run the test suite:

```bash
npm test
```

---

## Project Structure

The project is organized as follows:

```
adscript/
├── src/
│   ├── auth/         # Authentication modules
│   ├── backup/       # Backup management
│   ├── policy/       # Group Policy management
│   ├── replication/  # Data replication
│   ├── security/     # Security modules
│   ├── schema/       # Database schema
│   ├── logger/       # Logging setup
│   └── server.js     # Main server implementation
├── tests/            # Test cases
├── config/           # Configuration files
├── package.json      # Project dependencies and scripts
└── README.md         # Documentation
```

---

## License

This project is licensed under the **ISC License**. See the `LICENSE` file for details.

---

Happy coding! 🚀
