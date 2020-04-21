#!/usr/bin/env node

const cdk = require('@aws-cdk/core');
const { SecuritySupportStack } = require('../lib/security_support-stack');

const app = new cdk.App();
new SecuritySupportStack(app, 'SecuritySupportStack');
