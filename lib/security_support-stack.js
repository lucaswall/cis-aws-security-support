
const cdk = require('@aws-cdk/core');
const sns = require('@aws-cdk/aws-sns');
const lambda = require('@aws-cdk/aws-lambda');
const cloudtrail = require('@aws-cdk/aws-cloudtrail');
const s3 = require('@aws-cdk/aws-s3');
const ssm = require('@aws-cdk/aws-ssm');
const logs = require('@aws-cdk/aws-logs');
const cloudwatch = require('@aws-cdk/aws-cloudwatch');
const cloudwatchactions = require('@aws-cdk/aws-cloudwatch-actions');
const lambdaeventsources = require('@aws-cdk/aws-lambda-event-sources');

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
      events: [new lambdaeventsources.SnsEventSource(securitySns)],
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

    const filterFailedAuthentication = new logs.MetricFilter(this, 'Filter-CIS-3.6-ConsoleAuthenticationFailure', {
      filterPattern: logs.FilterPattern.literal('{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}'),
      logGroup: securityTrailLogGroup,
      metricName: 'Metric-CIS-3.6-ConsoleAuthenticationFailure',
      metricNamespace: 'LogMetrics',
    });
    filterFailedAuthentication.node.addDependency(securityTrailLogGroup);

    const metricFailedAuthentication = new cloudwatch.Metric({
      metricName: 'Metric-CIS-3.6-ConsoleAuthenticationFailure',
      namespace: 'LogMetrics',
      period: cdk.Duration.minutes(1),
      statistic: 'sum',
    });

    const alarmFailedAuthentication = new cloudwatch.Alarm(this, 'Alarm-CIS-3.6-ConsoleAuthenticationFailure', {
      evaluationPeriods: 1,
      metric: metricFailedAuthentication,
      threshold: 0,
      alarmName: 'Alarm-CIS-3.6-ConsoleAuthenticationFailure',
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      period: cdk.Duration.minutes(1),
      statistic: 'sum',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    alarmFailedAuthentication.addAlarmAction(new cloudwatchactions.SnsAction(securitySns));

  }

}

module.exports = { SecuritySupportStack };
