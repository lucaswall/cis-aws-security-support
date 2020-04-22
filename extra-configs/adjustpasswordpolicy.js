
const AWS = require('aws-sdk');

const iam = new AWS.IAM();

(async function() {
    
    const params = {
        AllowUsersToChangePassword: true,
        HardExpiry: false,
        MaxPasswordAge: 90,
        MinimumPasswordLength: 14,
        PasswordReusePrevention: 24,
        RequireLowercaseCharacters: true,
        RequireNumbers: true,
        RequireSymbols: true,
        RequireUppercaseCharacters: true
    };
    await iam.updateAccountPasswordPolicy(params).promise();
    
    const policy = await iam.getAccountPasswordPolicy({}).promise();
    console.log(policy);
    
})();
