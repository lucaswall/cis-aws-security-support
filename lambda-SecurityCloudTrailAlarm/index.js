'use strict';

const https = require('https');
const url = require('url');

const prefix = process.env.SLACK_PREFIX;
const webhookPath = process.env.SLACK_WEBHOOKPATH;

function postMessage(message, callback) {
    const body = JSON.stringify(message);
    const options = url.parse(webhookPath);
    options.method = 'POST';
    options.headers = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
    };

    const postReq = https.request(options, (res) => {
        const chunks = [];
        res.setEncoding('utf8');
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
            if (callback) {
                callback({
                    body: chunks.join(''),
                    statusCode: res.statusCode,
                    statusMessage: res.statusMessage,
                });
            }
        });
        return res;
    });

    postReq.write(body);
    postReq.end();
}

exports.handler = (event, context, callback) => {
    console.log("EVENT RECEIVED: ", JSON.stringify(event));

    try {

        const message = event.Records[0].Sns.Message;
        const parsedMessage = JSON.parse(message);
        const payload = {
            text: `:rotating_light: [${prefix}] *${parsedMessage.AlarmName}* ${parsedMessage.StateChangeTime} ${parsedMessage.Region} (${parsedMessage.AWSAccountId})`
        };

        postMessage(payload, (response) => {
            if (response.statusCode < 400) {
                console.info('Message posted successfully');
                callback(null);
            } else if (response.statusCode < 500) {
                console.error(`Error posting message to Slack API: ${response.statusCode} - ${response.statusMessage}`);
                callback(null);
            } else {
                callback(`Server error when processing message: ${response.statusCode} - ${response.statusMessage}`);
            }
        });

    } catch (error) {
        console.error(error);
        callback(JSON.stringify(error));
    }

};
