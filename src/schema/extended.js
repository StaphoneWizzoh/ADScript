// src/schema/extended.js
const extendedSchema = {
    user: {
        additionalAttributes: [
            "title",
            "department",
            "company",
            "manager",
            "employeeID",
            "employeeType",
            "extensionAttribute1",
            "extensionAttribute2",
        ],
    },
    group: {
        additionalAttributes: [
            "scope",
            "type",
            "managedBy",
            "info",
            "groupType",
        ],
    },
};

// ALTER TABLE users ADD COLUMN title TEXT;
// ALTER TABLE users ADD COLUMN department TEXT;
// ALTER TABLE users ADD COLUMN manager TEXT;
// ALTER TABLE users ADD COLUMN employeeID TEXT;

// ALTER TABLE groups ADD COLUMN scope TEXT;
// ALTER TABLE groups ADD COLUMN groupType INTEGER;
// ALTER TABLE groups ADD COLUMN managedBy TEXT;
