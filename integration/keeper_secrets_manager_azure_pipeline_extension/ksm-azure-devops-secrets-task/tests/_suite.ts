import * as path from 'path';
import * as assert from 'assert';
import * as ttm from 'azure-pipelines-task-lib/mock-test';

describe('Sample task tests', function () {
    this.timeout(10000); // Increase timeout to 10 seconds

    before(function() {
        process.env['TASK_TEST_TRACE'] = '1';
        process.env['SYSTEM_DEBUG'] = 'true';
    });

    after(() => {
        delete process.env['TASK_TEST_TRACE'];
        delete process.env['SYSTEM_DEBUG'];
    });

    it('should succeed with simple inputs', function(done: Mocha.Done) {
        this.timeout(5000);

        let tp = path.join(__dirname, 'success.js');
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.runAsync().then(() => {
            console.log(tr.stdout);
            console.log(tr.stderr);

            assert.equal(tr.succeeded, true, 'should have succeeded');
            assert.equal(tr.warningIssues.length, 0, "should have no warnings");
            assert.equal(tr.errorIssues.length, 0, "should have no errors");

            done();
        }).catch((err) => {
            done(err);
        });
    });
});