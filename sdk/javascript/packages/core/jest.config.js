process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

module.exports = {
    "roots": [
        "<rootDir>/test"
    ],
    "transform": {
        "^.+\\.(ts|tsx)$": "ts-jest"
    },
}
