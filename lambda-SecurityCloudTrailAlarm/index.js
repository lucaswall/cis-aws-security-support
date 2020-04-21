'use strict';

const https = require('https');

exports.handler = (event, context, callback) => {
    console.log("EVENT RECEIVED: ", JSON.stringify(event));

    try {

		const prefix = process.env.SLACK_PREFIX;
		const webhookPath = process.env.SLACK_WEBHOOKPATH;

        const message = event.Records[0].Sns.Message;
        const parsedMessage = JSON.parse(message);
        const payload = JSON.stringify({
            text: `:rotating_light: [${prefix}] *${parsedMessage.AlarmName}* ${parsedMessage.StateChangeTime} ${parsedMessage.Region} (${parsedMessage.AWSAccountId})`
        });

        const options = {
            hostname: 'hooks.slack.com',
            method: 'POST',
            path: webhookPath,
        };

        const req = https.request(options, (res) => res.on("data", () => callback(null, "Success")));
        req.on("error", (error) => callback(JSON.stringify(error)));
        req.write(payload);
        req.end();

    } catch (error) {
        console.error(error);
        callback(JSON.stringify(error));
    }

};
