'use strict';

const https = require('https');
const url = require('url');
const AWS = require('aws-sdk');

const iam = new AWS.IAM();

const prefix = process.env.SLACK_PREFIX;
const webhookPath = process.env.SLACK_WEBHOOKPATH;

function getAgeInDays(d) {
    return Math.floor((Date.now() - Date.parse(d)) / (1000 * 60 * 60 * 24));
}

async function processAccessKeysForUser(userName) {
    let msg = '';
    while (true) {
        const params = { UserName: userName };
        const accessKeys = await iam.listAccessKeys(params).promise();
        for (const key of accessKeys.AccessKeyMetadata) {
            const age = getAgeInDays(key.CreateDate);
            if (age >= 90 && key.Status == 'Active') {
                msg += `${key.UserName} AccessKey too old ${key.AccessKeyId} ${key.Status} ${age}d\n`;
            }
        }
        if (!accessKeys.IsTruncated) break;
        params.Marker = accessKeys.Marker;
    }
    return msg;
}

function postMessage(message) {
    return new Promise((fulfill, reject) => {
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
            res.on('error', (error) => reject(JSON.stringify(error)));
            res.on('end', () => {
                fulfill({
                    body: chunks.join(''),
                    statusCode: res.statusCode,
                    statusMessage: res.statusMessage,
                });
            });
            return res;
        });

        postReq.write(body);
        postReq.end();
    });
}

exports.handler = async (event, context, callback) => {

    try {

        let msg = '';
        const listUsersParams = {};
        while (true) {
            const users = await iam.listUsers(listUsersParams).promise();
            for (const user of users.Users) {
                msg += await processAccessKeysForUser(user.UserName);
                if (user.PasswordLastUsed) {
                    const age = getAgeInDays(user.PasswordLastUsed);
                    if (age >= 80) {
                        msg += `${user.UserName} no login in ${age} days.\n`;
                    }
                }
            }
            if (!users.IsTruncated) break;
            listUsersParams.Marker = users.Marker;
        }

        if (msg.length > 0) {
            console.log(msg);
            const response = await postMessage({ text: `*Problems found on users of account ${prefix}*\n${msg}` });
            if (response.statusCode < 400) {
                console.info('Message posted successfully');
                callback(null);
            } else if (response.statusCode < 500) {
                console.error(`Error posting message to Slack API: ${response.statusCode} - ${response.statusMessage}`);
                callback(null);
            } else {
                callback(`Server error when processing message: ${response.statusCode} - ${response.statusMessage}`);
            }
        }

    } catch (error) {
        console.error(error);
        callback(JSON.stringify(error));
    }

};
