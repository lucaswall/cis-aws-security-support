
const cdk = require('@aws-cdk/core');
const sns = require('@aws-cdk/aws-sns');
const lambda = require('@aws-cdk/aws-lambda');
const lambdaeventsources = require('@aws-cdk/aws-lambda-event-sources');
const cloudtrail = require('@aws-cdk/aws-cloudtrail');
const s3 = require('@aws-cdk/aws-s3');
const ssm = require('@aws-cdk/aws-ssm');
const events = require('@aws-cdk/aws-events');
const eventstargets = require('@aws-cdk/aws-events-targets');
const iam = require('@aws-cdk/aws-iam');
const kms = require('@aws-cdk/aws-kms');

const { CloudTrailAlarm } = require('./cloud-trail-alarm');

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

    const securityHubFindingsToSlackLambda = new lambda.Function(this, 'SecurityHubFindingsToSlack', {
      runtime: lambda.Runtime.NODEJS_12_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda-SecurityHubFindingsToSlack'),
      environment: {
        SLACK_PREFIX: ssm.StringParameter.valueForStringParameter(this, 'SecuritySupport_SlackPrefix'),
        SLACK_WEBHOOKPATH: ssm.StringParameter.valueForStringParameter(this, 'SecuritySupport_SlackWebHook'),
      }
    });
    
    new events.Rule(this, 'SecurityHubFindingsToSlackRule', {
      ruleName: 'SecurityHubFindingsToSlackRule',
      eventPattern: {
        source: ['aws.securityhub'],
        resources: [`arn:aws:securityhub:${this.region}:${this.account}:action/custom/SendToSlack`],
      },
      targets: [new eventstargets.LambdaFunction(securityHubFindingsToSlackLambda)],
    });

    const checkUserCreentialsLambda = new lambda.Function(this, 'CheckUsersCredentials', {
      runtime: lambda.Runtime.NODEJS_12_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda-CheckUsersCredentials'),
      environment: {
        SLACK_PREFIX: ssm.StringParameter.valueForStringParameter(this, 'SecuritySupport_SlackPrefix'),
        SLACK_WEBHOOKPATH: ssm.StringParameter.valueForStringParameter(this, 'SecuritySupport_SlackWebHook'),
      }
    });
    const checkUserCreentialsPolicy = new iam.PolicyStatement();
    checkUserCreentialsPolicy.addActions(['iam:listUsers', 'iam:listAccessKeys']);
    checkUserCreentialsPolicy.addAllResources();
    checkUserCreentialsLambda.addToRolePolicy(checkUserCreentialsPolicy);

    new events.Rule(this, 'CheckUsersCredentialsRule', {
      ruleName: 'CheckUsersCredentialsRule',
      schedule: events.Schedule.expression('cron(0 12 * * ? *)'),
      targets: [new eventstargets.LambdaFunction(checkUserCreentialsLambda)],
    });

    new sns.Subscription(this, 'SecurityCloudTrailAlarmSubscription', {
      topic: securitySns,
      protocol: sns.SubscriptionProtocol.LAMBDA,
      endpoint: cloudTrailAlarmLambda.functionArn,
    });

    const securityTrailBucketAccessLog = new s3.Bucket(this, 'SecurityTrailAccessLog', {
    });

    const securityTrailBucket = new s3.Bucket(this, 'SecurityTrail', {
      serverAccessLogsBucket: securityTrailBucketAccessLog,
    });

    const securityTrailKey = new kms.Key(this, 'SecurityTrailKey', {
      enableKeyRotation: true,
      description: 'CloudTrail logs encryptation key',
    });

    securityTrailKey.addToResourcePolicy(new iam.PolicyStatement({
      resources: ['*'],
      actions: ['kms:GenerateDataKey*'],
      principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
      conditions: {
        StringLike: { 'kms:EncryptionContext:aws:cloudtrail:arn': `arn:aws:cloudtrail:*:${this.account}:trail/*` },
      },
    }));

    const securityTrail = new cloudtrail.Trail(this, 'SecurityFullTrail', {
      isMultiRegionTrail: true,
      bucket: securityTrailBucket,
      sendToCloudWatchLogs: true,
      kmsKey: securityTrailKey,
    });

    const securityTrailLogGroup = securityTrail.node.findChild('LogGroup');
    securityTrailLogGroup.logGroupName = 'SecurityTrailLog';

    const cloudTrailAlarmList = [
      { id: 'CIS-1.1-RootAccountUsage', filter: '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}' },
      { id: 'CIS-3.1-UnauthorizedAPICalls', filter: '{($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")}' },
      { id: 'CIS-3.2-ConsoleSigninWithoutMFA', filter: '{($.eventName="ConsoleLogin") && ($.additionalEventData.MFAUsed !="Yes")}' },
      { id: 'CIS-3.3-RootAccountUsage', filter: '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}' },
      { id: 'CIS-3.4-IAMPolicyChanges', filter: '{($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy)}' },
      { id: 'CIS-3.5-CloudTrailChanges', filter: '{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}' },
      { id: 'CIS-3.6-ConsoleAuthenticationFailure', filter: '{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}' },
      { id: 'CIS-3.7-DisableOrDeleteCMK', filter: '{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}' },
      { id: 'CIS-3.8-S3BucketPolicyChanges', filter: '{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}' },
      { id: 'CIS-3.9-AWSConfigChanges', filter: '{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}' },
      { id: 'CIS-3.10-SecurityGroupChanges', filter: '{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}' },
      { id: 'CIS-3.11-NetworkACLChanges', filter: '{($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)}' },
      { id: 'CIS-3.12-NetworkGatewayChanges', filter: '{($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)}' },
      { id: 'CIS-3.13-RouteTableChanges', filter: '{($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)}' },
      { id: 'CIS-3.14-VPCChanges', filter: '{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}' },
    ];

    for (const d of cloudTrailAlarmList) {
      new CloudTrailAlarm(this, d.id, {
        logGroup: securityTrailLogGroup,
        reportSnsTopic: securitySns,
        filterPatternString: d.filter,
      });
    }

    new iam.Role(this, 'SupportAccess', {
      assumedBy: new iam.AccountPrincipal(this.account),
      roleName: 'SupportAccess',
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('AWSSupportAccess')],
    });

  }

}

module.exports = { SecuritySupportStack };
