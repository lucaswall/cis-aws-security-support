
const AWS = require('aws-sdk');

const securityhub = new AWS.SecurityHub();

(async function() {

    await securityhub.createActionTarget({
        Description: 'This custom action sends selected findings as channel in a Slack Workspace',
        Id: 'SendToSlack',
        Name: 'Send to Slack',
    }).promise();

})();
