
const cdk = require('@aws-cdk/core');
const logs = require('@aws-cdk/aws-logs');
const cloudwatch = require('@aws-cdk/aws-cloudwatch');
const cloudwatchactions = require('@aws-cdk/aws-cloudwatch-actions');

class CloudTrailAlarm extends cdk.Construct {
  constructor(scope, id, props) {
    super(scope, id, props);

    const filter = new logs.MetricFilter(this, 'Filter', {
      filterPattern: logs.FilterPattern.literal(props.filterPatternString),
      logGroup: props.logGroup,
      metricName: 'SecurityMetric-'+id,
      metricNamespace: 'LogMetrics',
    });
    filter.node.addDependency(props.logGroup);

    const metric = new cloudwatch.Metric({
      metricName: 'SecurityMetric-'+id,
      namespace: 'LogMetrics',
      period: cdk.Duration.minutes(1),
      statistic: 'sum',
    });

    const alarm = new cloudwatch.Alarm(this, 'Alarm', {
      evaluationPeriods: 1,
      metric: metric,
      threshold: 0,
      alarmName: 'SecurityAlarm-'+id,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      period: cdk.Duration.minutes(1),
      statistic: 'sum',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    alarm.addAlarmAction(new cloudwatchactions.SnsAction(props.reportSnsTopic));

  }
}

module.exports = { CloudTrailAlarm };
