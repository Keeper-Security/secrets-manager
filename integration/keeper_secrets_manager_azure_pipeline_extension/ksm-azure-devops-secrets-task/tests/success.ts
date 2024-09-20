import * as tmrm from "azure-pipelines-task-lib/mock-run"
import * as path from "path"
import * as dotenv from 'dotenv'
import * as fs from 'fs'

// Load environment variables from .env file
dotenv.config();

console.log('Debug: Starting test setup');

let taskPath = path.join(__dirname, '..', 'index.js');
console.log(`Debug: Task path is ${taskPath}`);

// Check if the index.js file exists
if (fs.existsSync(taskPath)) {
    console.log('Debug: index.js file found');
} else {
    console.log('Debug: index.js file not found');
}

let tmr: tmrm.TaskMockRunner = new tmrm.TaskMockRunner(taskPath);

// Use KEEPER_CONFIG from environment variables
const keeperConfig = process.env.KEEPER_CONFIG || '';
console.log(`Debug: KEEPER_CONFIG length: ${keeperConfig.length}`);
console.log(`Debug: KEEPER_CONFIG starts with: ${keeperConfig.substring(0, 20)}...`);

tmr.setInput('keepersecretconfig', keeperConfig);

const secrets = 'xtlguWgodbpFkKJn7_7mAQ/field/password > var:MYPWD123\n' +
    'xtlguWgodbpFkKJn7_7mAQ/field/password > var:MYPWD123\n' +
    'xtlguWgodbpFkKJn7_7mAQ/field/password > out:outpwd\n' +
    'xtlguWgodbpFkKJn7_7mAQ/field/password > outpwd2\n' +
    '6ya_fdc6XTsZ7i7x9Jcodg/file/build-vsix.sh > file:/tmp/build-vsix.sh';

console.log(`Debug: Secrets input: ${secrets}`);

tmr.setInput('secrets', secrets);

// Mock any necessary functions or modules
console.log('Debug: Setting up mocks');

// Example: Mock a function
tmr.registerMock('azure-pipelines-task-lib/toolrunner', {
    execSync: function(cmd: string, options: any) {
        console.log(`Debug: Mocked execSync called with command: ${cmd}`);
        return 'mocked output';
    }
});

console.log('Debug: Starting test run');
tmr.run();
console.log('Debug: Test run completed');