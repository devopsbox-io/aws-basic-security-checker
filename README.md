# AWS Basic security checker

This tool was created to constantly check basic security of a multi or single account AWS organization. Currently, it
checks if:

- there are any old API keys
- users didn't change their passwords for a long time
- users have MFA enabled

Additionally it sets:

- Service Control Policy that denies root access on every child account in your organization
- account password policy

# Installation

## Prerequisites

- Pulumi (tested with v3.27.0) - Infrastructure as Code tool used to create AWS resources. You can install Pulumi using:

```shell
curl -sSL https://get.pulumi.com | sh
```

- Node.js (tested with v12.18.3)
- npm (tested with 6.14.8)
- AWS credentials required to create all the resources on the management (master) account
- Verified email or domain in AWS SES. You should verify admin and every users' email. We recommend verifying a domain
  instead of every single email.
- Child accounts in your AWS Organization must have the "OrganizationAccountAccessRole" which can be assumed from
  organizations management (master) account. This role is created by default when you create an account using AWS
  Organizations.

## Pulumi configuration

You can use any type of Pulumi backend and secret encryption provider.

This README assumes s3 as a Pulumi backend and kms as a secret encryption provider - we are using this combination. To
use the same setting you have to:

- create an S3 bucket called `pulumi-state-AWS_ACCOUNT_NUMBER` (for example `pulumi-state-123456789012`)
- create a KMS key with a `pulumi-secret-encryption` alias

## Getting the code

You can just clone or download this code from github. For example

```shell
git clone git@github.com:devopsbox-io/aws-basic-security-checker.git
```

Then you have to install all the required dependencies:

```shell
npm install
```

## Configuration parameters

To set configuration parameters, you need to create a Pulumi stack:

```shell
pulumi stack init --secrets-provider="awskms://alias/pulumi-secret-encryption" aws-basic-security-checker.prod
```

We are using "prod" because we consider created resources as production. You can use a different name for example if you
want to modify and test this project.

Probably you want to commit the newly created configuration file to some git repository. You can move the file to
another directory to do this:

```shell
mv Pulumi.aws-basic-security-checker.prod.yaml ../aws-basic-security-checker-YOUR_ORGANIZATION/Pulumi.aws-basic-security-checker.prod.yaml
```

Now you can add all the configuration parameters:

```yaml
config:
  aws-basic-security-checker:adminEmail: admin@tmp.org
  aws-basic-security-checker:dryRun: "true"
  aws-basic-security-checker:skipAccounts:
    - "123456789013"
    - "123456789014"
  aws:region: eu-west-1
```

Required parameters:

- `aws:region` AWS region in which you want aws-basic-security-checker to be installed
- `aws-basic-security-checker:dryRun` If set to `false` aws-basic-security-checker will automatically deactivate access
  keys, console access or force users to assign an MFA device
- `aws-basic-security-checker:adminEmail` Email address used for admin notifications and as a source email for users'
  notifications.

Optional parameters:

- `aws-basic-security-checker:skipAccounts` List of AWS accounts you don't want to be verified. It must be a `string`
  array.

## Creating AWS resources

```shell
pulumi up --stack aws-basic-security-checker.prod --config-file ../aws-basic-security-checker-YOUR_ORGANIZATION/Pulumi.aws-basic-security-checker.prod.yaml
```

# User tags

aws-basic-security-checker behaviour can be customized using one of the following tags created on an IAM user:

- `Email` required - this is the email that will be used to notify the user about password, access key expiration or the
  need to assing an MFA device
- `MFANotRequired` - Set this tag value to "true" if you don't want to force MFA for this user.
- `LockAccessKeyExpiration` - Set this tag value to "true" if you don't want to force user to rotate API keys.

# How it works?

## AWS Resources

aws-basic-security-checker creates multiple AWS resources:

On the management (master account):

- Service Control Policy which denies root access on every child account in your organization
- IAM group which will be used to force users to assign an MFA device
- Account password policy
- For every account in the organization:
    - Lambda function executed from cron (AWS Events Bridge) "0 10 * * ? *"
    - IAM role required by the Lambda function

On every child account:

- IAM group which will be used to force users to assign an MFA device
- Account password policy
- Iam role to be assumed by a Lambda function created on the main/management account

## Lambda functions

Every lambda function is executed every day at 10 UTC. Each function is responsible for a single AWS account, and it
does the following things:

- every root user is checked if:
    - has MFA enabled
    - has access key older than 90 days

If one of conditions is not met, notification is sent to the admin user (email configured as an adminEmail pulumi config
param)

- every non-root IAM user is checked if:
    - has an `Email` tag - if no, the admin is notified and all the further user notifications are not possible
    - the password has been changed more than 90 ago - if yes, the user is notified
    - the password has been changed more than 120 ago - if yes the console login is being disabled (if not in the dry
      run mode)
    - has an active MFA device or has an `MFANotRequired` tag with value `true` - if not the user is added to
      the `MFARequired` IAM group (if not in the dry run mode) - it has only permissions to add an MFA device. A
      notification to both the user and the admin is sent.
    - has an MFA device and is in the `MFARequired` IAM group - the user is automatically removed from the group (if not
      in the dry run mode) and a notification to the admin is sent.
    - has a `LockAccessKeyExpiration` tag with value `true` - if yes, checking access key (next two bullet points) is
      disabled
    - has an access key older than 90 days - a notification is sent to the user
    - has an access key older than 120 - the key is being disabled (if not in the dry run mode) and a notification is
      sent to the admin

# Uninstallation

```shell
pulumi destroy --stack aws-basic-security-checker.prod --config-file ../aws-basic-security-checker-YOUR_ORGANIZATION/Pulumi.aws-basic-security-checker.prod.yaml
```
