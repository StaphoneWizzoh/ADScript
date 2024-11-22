// tests/server.test.js
const assert = require("assert");
const ldap = require("ldapjs");
const { ADServer } = require("../src/server");
const path = require("path");

describe("AD Server Tests", () => {
    let server;
    let client;
    let groupService;

    const testConfig = {
        host: "localhost",
        port: 1389,
        baseDN: "dc=test,dc=com",
        dbPath: path.join(__dirname, "test.sqlite"),
    };

    before(async () => {
        server = new ADServer(testConfig);
        await new Promise((resolve) => {
            server.start();
            setTimeout(resolve, 1000);
        });

        client = ldap.createClient({
            url: `ldap://${testConfig.host}:${testConfig.port}`,
        });
    });

    after(() => {
        client.unbind();
        server.stop();
        require("fs").unlinkSync(testConfig.dbPath);
    });

    describe("Authentication", () => {
        beforeEach(async () => {
            await server.addUser({
                sAMAccountName: "testuser",
                userPrincipalName: "testuser@test.com",
                password: "password123",
            });
        });

        it("should authenticate valid credentials", (done) => {
            client.bind("cn=testuser,dc=test,dc=com", "password123", (err) => {
                assert(!err);
                done();
            });
        });

        it("should reject invalid credentials", (done) => {
            client.bind(
                "cn=testuser,dc=test,dc=com",
                "wrongpassword",
                (err) => {
                    assert(err);
                    assert.equal(err.code, 49);
                    done();
                }
            );
        });
    });

    describe("Group Management", () => {
        beforeEach(async () => {
            groupService = server.groupService;
            await server.addGroup({
                cn: "TestGroup",
                description: "Test Group",
            });
            await server.addUser({
                sAMAccountName: "groupuser",
                userPrincipalName: "groupuser@test.com",
                password: "testpass",
            });
        });

        it("should add user to group", async () => {
            await groupService.addUserToGroup("groupuser", "TestGroup");
            const isMember = await groupService.isUserMemberOf(
                "groupuser",
                "TestGroup"
            );
            assert(isMember);
        });
    });
});
