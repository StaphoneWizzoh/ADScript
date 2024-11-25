const { ADServer } = require("../server");

async function seedData() {
    const server = new ADServer({
        host: "localhost",
        port: 3389,
        baseDN: "dc=test,dc=com",
    });

    try {
        // Add mock users
        await server.addUser({
            sAMAccountName: "jdoe",
            userPrincipalName: "john.doe@test.com",
            password: "password123",
        });

        await server.addUser({
            sAMAccountName: "asmith",
            userPrincipalName: "alice.smith@test.com",
            password: "password456",
        });

        // Add mock groups
        await server.addGroup({
            cn: "Admins",
            description: "Administrators group",
        });

        await server.addGroup({
            cn: "Users",
            description: "Regular users group",
        });

        // Add users to groups
        await server.groupService.addUserToGroup("jdoe", "Admins");
        await server.groupService.addUserToGroup("asmith", "Users");

        console.log("Database seeded successfully!");
    } catch (err) {
        console.error("Error seeding database:", err);
    } finally {
        await server.stop();
    }
}

seedData();
