import ma = require('azure-pipelines-task-lib/mock-answer');
import tmrm = require('azure-pipelines-task-lib/mock-run');
import path = require('path');

let taskPath = path.join(__dirname, '..', 'index.js');
let tmr: tmrm.TaskMockRunner = new tmrm.TaskMockRunner(taskPath);

tmr.setInput('keepersecretconfig', '{"hostname": "keepersecurity.com","clientId": "EI5T2FnqeqZuFk5TgKvX7ba13DF5caY9xTIUWOoiKcwf+l8VdKQ7QNOFSa9KOeH+BJ2M/VPOh5+yTFARgHTGsQ==","privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAvyxmlcjBkr0gUmWJFh6syA/i55JrsrqrEbQfVlQriuhRANCAARmUagZnWeA7SboYIPW42RC6k+DrqpBQymln2ZLMVzRQIo2rQ2iZ/WWbEZklljgnuwIia1Ojze+iFtHiFZFDuKC","serverPublicKeyId": "10","appKey": "nDejWN1Lb/VifIglwxGc0hZcUefxPWewf03LLGeoei0="}');
tmr.setInput('secrets', 'xtlguWgodbpFkKJn7_7mAQ/field/password > var:MYPWD123\n' +
    'xtlguWgodbpFkKJn7_7mAQ/field/password > var:MYPWD123\n' +
    'xtlguWgodbpFkKJn7_7mAQ/field/password > out:outpwd\n' +
    'xtlguWgodbpFkKJn7_7mAQ/field/password > outpwd2\n' +
    '6ya_fdc6XTsZ7i7x9Jcodg/file/build-vsix.sh > file:/tmp/build-vsix.sh'); // pwd should be `Flor15TPa$$w0rd`


tmr.run();
