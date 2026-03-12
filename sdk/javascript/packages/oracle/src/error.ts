export class OracleKeyValueStorageError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'OracleKeyValueStorageError';
    }
}