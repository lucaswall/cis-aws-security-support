
const cdk = require('@aws-cdk/core');
const sns = require('@aws-cdk/aws-sns');
const lambda = require('@aws-cdk/aws-lambda');
const cloudtrail = require('@aws-cdk/aws-cloudtrail');
const s3 = require('@aws-cdk/aws-s3');
const ssm = require('@aws-cdk/aws-ssm');
const logs = require('@aws-cdk/aws-logs');

class SecuritySupportStack extends cdk.Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const securitySns = new sns.Topic(this, 'SecurityAlarmsTopic', {
      topicName: 'SecurityAlarms'
    });

    const cloudTrailAlarmLambda = new lambda.Function(this, 'SecurityCloudTrailAlarm', {
      runtime: lambda.Runtime.NODEJS_12_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda-SecurityCloudTrailAlarm'),
      environment: {
        SLACK_PREFIX: ssm.StringParameter.valueForStringParameter(this, 'SecuritySupport_SlackPrefix'),
        SLACK_WEBHOOKPATH: ssm.StringParameter.valueForStringParameter(this, 'SecuritySupport_SlackWebHook'),
      }
    });

    new sns.Subscription(this, 'SecurityCloudTrailAlarmSubscription', {
      topic: securitySns,
      protocol: sns.SubscriptionProtocol.LAMBDA,
      endpoint: cloudTrailAlarmLambda.functionArn,
    });

    const securityTrailBucket = new s3.Bucket(this, 'SecurityTrail', {
    });

    const securityTrail = new cloudtrail.Trail(this, 'SecurityFullTrail', {
      isMultiRegionTrail: true,
      bucket: securityTrailBucket,
      sendToCloudWatchLogs: true,
    });

    const securityTrailLogGroup = securityTrail.node.findChild('LogGroup');
    securityTrailLogGroup.logGroupName = 'SecurityTrailLog';

    const filterFailedAuthentication = new logs.MetricFilter(this, 'FilterFailedAuthentication', {
      filterPattern: logs.FilterPattern.literal('{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}'),
      logGroup: securityTrailLogGroup,
      metricName: 'CIS-3.6-ConsoleAuthenticationFailure',
      metricNamespace: 'SecurityAlerts'
    });
    filterFailedAuthentication.node.addDependency(securityTrailLogGroup);

  }

}

module.exports = { SecuritySupportStack };
