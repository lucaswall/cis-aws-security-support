const AWS = require('aws-sdk');

const iam = new AWS.IAM();

function getAgeInDays(d) {
    return Math.floor((Date.now() - Date.parse(d)) / (1000 * 60 * 60 * 24));
}

async function processAccessKeysForUser(userName) {
    while (true) {
        const params = { UserName: userName };
        const accessKeys = await iam.listAccessKeys(params).promise();
        for (const key of accessKeys.AccessKeyMetadata) {
            const age = getAgeInDays(key.CreateDate);
            if (age >= 90 && key.Status == 'Active') {
                console.log(`${key.UserName} AccessKey too old ${key.AccessKeyId} ${key.Status} ${age}d`);
            }
        }
        if (!accessKeys.IsTruncated) break;
        params.Marker = accessKeys.Marker;
    }
}

(async function() {

    const listUsersParams = {};
    while (true) {
        const users = await iam.listUsers(listUsersParams).promise();
        for (const user of users.Users) {
            processAccessKeysForUser(user.UserName);
            if (user.PasswordLastUsed) {
                const age = getAgeInDays(user.PasswordLastUsed);
                if (age >= 30) {
                    console.log(`${user.UserName} no login in ${age} days.`);
                }
            }
        }
        if (!users.IsTruncated) break;
        listUsersParams.Marker = users.Marker;
    }

})();
