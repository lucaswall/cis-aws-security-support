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
    console.log('EVENT RECEIVED: ', JSON.stringify(event));

    try {

        let color = '#0073bb';
        let severity = 'NONE';
        switch (true) {
            case (event.detail.severity <= 3.9 && event.detail.severity >= 0):
                color = '#0073bb';
                severity = 'LOW';
                break;
            case (event.detail.severity <= 6.9 && event.detail.severity >= 4):
                color = '#eb5f07';
                severity = 'MID';
                break;
            case (event.detail.severity <= 8.9 && event.detail.severity >= 7):
                color = '#d13212';
                severity = 'HIGH';
                break;
        }

        const additionalInfo = JSON.stringify(event.detail.service.additionalInfo);
        const attachment = {
            'fallback': `:shield: [${prefix}] ${severity} ${event.detail.region} ${event.detail.resource.resourceType} ${event.detail.service.eventLastSeen} ${additionalInfo}`,
            'color': color,
            'title': `:shield: [${prefix}] ${event.detail.title}`,
            'text': `${event.detail.description}`,
            'fields': [
                {
                    'title': 'AccountId',
                    'value': `${event.detail.accountId}`,
                    'short': true
                },
                {
                    'title': 'Region',
                    'value': `${event.region}`,
                    'short': true
                },
                {
                    'title': 'Severity',
                    'value': `${severity}`,
                    'short': true
                },
                {
                    'title': 'Resource Type',
                    'value': `${event.detail.resource.resourceType}`,
                    'short': true
                },
                {
                    'title': 'Created',
                    'value': `${event.detail.createdAt}`,
                    'short': true
                },
                {
                    'title': 'Updated',
                    'value': `${event.detail.updatedAt}`,
                    'short': true
                },
            ],
        };

        const payload = {
            text: '',
            attachments: [attachment],
            username: 'GuardShield',
            'mrkdwn': true,
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
