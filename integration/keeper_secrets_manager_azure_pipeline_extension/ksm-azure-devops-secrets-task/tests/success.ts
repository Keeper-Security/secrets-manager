import * as tmrm from "azure-pipelines-task-lib/mock-run"
import * as path from "path"

let taskPath = path.join(__dirname, '..', 'index.js');
let tmr: tmrm.TaskMockRunner = new tmrm.TaskMockRunner(taskPath);

// @ts-ignore
let config_json: string = process.env.CONFIG_JSON

tmr.setInput('keepersecretconfig', config_json);
tmr.setInput('secrets', 'xtlguWgodbpFkKJn7_7mAQ/field/password > var:MYPWD123\n' +
    'xtlguWgodbpFkKJn7_7mAQ/field/password > var:MYPWD123\n' +
    'xtlguWgodbpFkKJn7_7mAQ/field/password > out:outpwd\n' +
    'xtlguWgodbpFkKJn7_7mAQ/field/password > outpwd2\n' +
    '6ya_fdc6XTsZ7i7x9Jcodg/file/build-vsix.sh > file:/tmp/build-vsix.sh'); // pwd should be `Flor15TPa$$w0rd`

tmr.run();
