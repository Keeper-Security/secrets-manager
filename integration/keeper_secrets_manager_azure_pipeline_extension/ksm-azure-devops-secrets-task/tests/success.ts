import * as tmrm from "azure-pipelines-task-lib/mock-run"
import * as path from "path"

let taskPath = path.join(__dirname, '..', 'index.js');
let tmr: tmrm.TaskMockRunner = new tmrm.TaskMockRunner(taskPath);

// Provide a dummy config (the mock below intercepts all SDK calls so this is never sent to a real server)
tmr.setInput('keepersecretconfig', '{"clientId":"mock","privateKey":"mock","serverPublicKeyId":"10","appKey":"mock","hostname":"keepersecurity.com","appOwnerPublicKey":"mock"}');

const secrets = 'xtlguWgodbpFkKJn7_7mAQ/field/password > var:MYPWD123\n' +
    'xtlguWgodbpFkKJn7_7mAQ/field/password > var:MYPWD123\n' +
    'xtlguWgodbpFkKJn7_7mAQ/field/password > out:outpwd\n' +
    'xtlguWgodbpFkKJn7_7mAQ/field/password > outpwd2\n' +
    '6ya_fdc6XTsZ7i7x9Jcodg/file/build-vsix.sh > file:/tmp/build-vsix.sh';

tmr.setInput('secrets', secrets);

// Mock the KSM SDK so the task runs without real vault credentials
tmr.registerMock('@keeper-security/secrets-manager-core', {
    loadJsonConfig: function(_config: string) {
        return { getString: function() { return '{}'; } };
    },
    getSecrets: async function(_options: any, _uids: string[]) {
        return {
            records: [
                { recordUid: 'xtlguWgodbpFkKJn7_7mAQ' },
                { recordUid: '6ya_fdc6XTsZ7i7x9Jcodg' }
            ]
        };
    },
    getValue: async function(_secrets: any, notation: string) {
        if (notation.includes('/file/')) {
            return { name: 'build-vsix.sh', title: 'build-vsix.sh', type: 'file' };
        }
        return 'mock-secret-value';
    },
    downloadFile: async function(_file: any) {
        return Buffer.from('mock file content');
    },
    parseNotation: function(notation: string) {
        const parts = notation.trim().split('/');
        // Return structure matching SDK: [prefix, {text: [uid]}, {text: [selector]}, {text: [field]}]
        return [
            { text: [''] },
            { text: [parts[0]] },
            { text: [parts[1]] },
            { text: [parts.slice(2).join('/')] }
        ];
    }
});

tmr.registerMock('azure-pipelines-task-lib/toolrunner', {
    execSync: function(cmd: string, _options: any) {
        return 'mocked output';
    }
});

tmr.run();
