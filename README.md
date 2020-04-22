# Security Support Stack

A simple AWS CDK script to deploy resources that resolve some CIS AWS Foundations Benchmark findings

While following repetitive directions to solve several security findings of the AWS Security Hub I ended
up wiriting this simple stack to be able to deploy the same resources on several accounts.

The stack itself will create resources to solve several CIS AWS Foundations findings.

The extra-config folder has scripts that adjust configurations and thus can not be done with a stack.

The stack will also deploy lambdas to send to Slack security CloudWatch alarms and Security Hub findings.

The following System Manager Parameter Store parameters must be set:

* SecuritySupport_SlackPrefix - a short string included in the slack messages (used to indicate the account this message is for).
* SecuritySupport_SlackWebHook - The http webhook used to send messages to slack.

## Useful commands

 * `npm run test`         perform the jest unit tests
 * `cdk deploy`           deploy this stack to your default AWS account/region
 * `cdk diff`             compare deployed stack with current state
 * `cdk synth`            emits the synthesized CloudFormation template

## Author

Lucas Wall <wall.lucas@gmail.com>

The SecurityHubFindingsToSlack lambda function is based no a sample by Amazon.
https://github.com/aws-samples/aws-securityhub-to-slack
