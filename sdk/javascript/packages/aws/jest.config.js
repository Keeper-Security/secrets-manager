module.exports = {
    "roots": [
        "<rootDir>/test"
    ],
    "transform": {
        "^.+\\.(ts|tsx)$": ["ts-jest", { tsconfig: "tsconfig.test.json" }]
    },
    "testEnvironment": "node"
}
