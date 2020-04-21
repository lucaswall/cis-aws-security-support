const { expect, matchTemplate, MatchStyle } = require('@aws-cdk/assert');
const cdk = require('@aws-cdk/core');
const SecuritySupport = require('../lib/security_support-stack');

test('Empty Stack', () => {
    const app = new cdk.App();
    // WHEN
    const stack = new SecuritySupport.SecuritySupportStack(app, 'MyTestStack');
    // THEN
    expect(stack).to(matchTemplate({
      "Resources": {}
    }, MatchStyle.EXACT))
});