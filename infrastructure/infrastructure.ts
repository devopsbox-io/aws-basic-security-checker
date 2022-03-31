import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import {FORCE_MFA_GROUP} from "../common/common";
import * as fs from "fs";
import {CredentialsChecker} from "../checker/credentials-checker";
import * as path from "path";

interface AwsAccount {
    name: string;
    resourceCreationRoleArn?: string;
    id: string;
    isManagement: boolean;
}

export class Infrastructure {
    async create() {
        const config = new pulumi.Config();
        const awsConfig = new pulumi.Config("aws");

        const adminEmail = config.require("adminEmail");
        const skipAccounts = config.getObject<string[]>("skipAccounts");
        const dryRun = config.requireBoolean("dryRun");
        const awsRegion = awsConfig.require("region");

        const callerIdentity = await aws.getCallerIdentity({});
        const managementAwsAccountId = callerIdentity.id;

        const functionArns = [];

        const accounts = await Infrastructure.getAwsAccounts(managementAwsAccountId);

        Infrastructure.createDenyRootAccessServiceControlPolicy();

        for (const account of accounts) {
            if (skipAccounts && skipAccounts.includes(account.id)) {
                console.log("Skipping account " + account.id);
            } else {
                const provider = Infrastructure.createAwsProvider(account.id, awsRegion, account.resourceCreationRoleArn);

                Infrastructure.createForceMFAIamGroup(provider, account.id);

                Infrastructure.createAccountPasswordPolicy(provider, account.id);

                const functionName = pulumi.getStack().replace(/\./g, "-") + "-" + account.id;

                const iamRoleToAssumeArn = account.isManagement ? "" : Infrastructure.roleArn(account.id, functionName);

                let iamRoleToAssume: aws.iam.Role;
                if (!account.isManagement) {
                    iamRoleToAssume = Infrastructure.createNonManagementAccountRole(
                        provider,
                        functionName,
                        Infrastructure.roleArn(managementAwsAccountId, Infrastructure.getManagementRoleName(functionName))
                    );
                }

                const eventRuleEventSubscription = Infrastructure.createLambda(functionName, adminEmail, dryRun, iamRoleToAssumeArn, account);

                functionArns.push(eventRuleEventSubscription.func.arn);
            }
        }

        return {
            functionArns: functionArns,
        };
    }

    private static createAwsProvider(providerName: string, region: string, roleArn?: string) {
        const providerArgs: aws.ProviderArgs = {
            region: region as aws.Region,
        };

        if (roleArn) {
            providerArgs.assumeRole = {
                roleArn: roleArn,
            };
        }

        return new aws.Provider(providerName, providerArgs);
    }

    private static createDenyRootAccessServiceControlPolicy() {
        const name = "DenyRootAccess";
        return new aws.organizations.Policy(name, {
            name: name,
            description: "Restrict root user access for member accounts",
            content: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    }
  ]
}
`,
        });
    }

    private static createLambdaRole(roleName: string, nonManagementRoleArn?: string) {
        const inlinePolicies = [
            Infrastructure.sesAccessPolicy(roleName + "-ses"),
        ];
        if (nonManagementRoleArn) {
            inlinePolicies.push(
                Infrastructure.assumeRolePolicy(roleName + "-assume", nonManagementRoleArn),
            );
        } else {
            inlinePolicies.push(
                Infrastructure.iamAccessPolicy(roleName + "-iam"),
            );
        }

        return new aws.iam.Role(roleName, {
            name: roleName,
            assumeRolePolicy: {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "",
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "lambda.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            managedPolicyArns: [
                aws.iam.ManagedPolicy.AWSLambdaBasicExecutionRole,
            ],
            inlinePolicies: inlinePolicies,
        });
    }

    private static createForceMFAIamGroup(provider: aws.Provider, awsAccountId: string) {
        const pulumiResourceName = FORCE_MFA_GROUP + "-" + awsAccountId;
        const group = new aws.iam.Group(pulumiResourceName, {
            name: FORCE_MFA_GROUP,
        }, {
            provider,
        });

        const policyFile = fs.readFileSync(path.resolve(__dirname, "force-mfa-policy.json"), "utf-8");
        const policy = new aws.iam.GroupPolicy(pulumiResourceName, {
            group: group.name,
            policy: policyFile,
        }, {
            provider,
        });

        return policy.group;
    }

    private static createAccountPasswordPolicy(provider: aws.Provider, awsAccountId: string) {
        const pulumiResourceName = "password-policy-" + awsAccountId;

        const policy = new aws.iam.AccountPasswordPolicy(pulumiResourceName, {
            allowUsersToChangePassword: true,
            hardExpiry: false,
            maxPasswordAge: 90,
            minimumPasswordLength: 15,
            passwordReusePrevention: 5,
            requireLowercaseCharacters: true,
            requireNumbers: true,
            requireSymbols: true,
            requireUppercaseCharacters: true,
        }, {
            provider,
        });

        return policy.id;
    }

    private static createNonManagementAccountRole(provider: pulumi.ProviderResource, roleName: string, trustedRoleArn: string) {
        return new aws.iam.Role(roleName, {
            name: roleName,
            assumeRolePolicy: {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": trustedRoleArn,
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            inlinePolicies: [
                Infrastructure.iamAccessPolicy(roleName + "-iam"),
            ],
        }, {
            provider,
        });
    }

    private static createLambda(functionName: string, adminEmail: string, dryRun: boolean, iamRoleToAssumeArn: string, account: AwsAccount) {
        const role = Infrastructure.createLambdaRole(Infrastructure.getManagementRoleName(functionName), iamRoleToAssumeArn);

        const lambdaCallbackFunction = new aws.lambda.CallbackFunction(functionName, {
            name: functionName,
            callback: async event => {
                const credentialsChecker = CredentialsChecker.createDefault({
                    dryRun: dryRun,
                    adminEmail: adminEmail,
                    iamRoleArn: iamRoleToAssumeArn,
                    awsAccountId: account.id,
                    isManagementAccount: account.isManagement,
                });
                await credentialsChecker.run();
            },
            role: role,
            timeout: 900,
        });

        return aws.cloudwatch.onSchedule(
            functionName,
            "cron(0 10 * * ? *)",
            lambdaCallbackFunction,
            {},
        );
    }

    private static iamAccessPolicy(name: string) {
        return {
            name: name,
            policy: JSON.stringify({
                Version: "2012-10-17",
                Statement: [
                    {
                        Effect: "Allow",
                        Action: [
                            "iam:ListUserTags",
                            "iam:ListGroupsForUser",
                            "iam:ListAccessKeys",
                            "iam:GetCredentialReport",
                            "iam:GenerateCredentialReport",
                            "iam:AddUserToGroup",
                            "iam:RemoveUserFromGroup",
                            "iam:DeleteLoginProfile",
                            "iam:UpdateAccessKey",
                        ],
                        Resource: [
                            "*",
                        ],
                    }],
            }),
        };
    }

    private static sesAccessPolicy(name: string) {
        return {
            name: name,
            policy: JSON.stringify({
                Version: "2012-10-17",
                Statement: [
                    {
                        Effect: "Allow",
                        Action: [
                            "ses:SendEmail",
                        ],
                        Resource: [
                            "*",
                        ],
                    }],
            }),
        };
    }

    private static assumeRolePolicy(name: string, roleArn: string) {
        return {
            name: name,
            policy: JSON.stringify({
                Version: "2012-10-17",
                Statement: [
                    {
                        Effect: "Allow",
                        Action: [
                            "sts:AssumeRole",
                        ],
                        Resource: [
                            roleArn,
                        ],
                    }],
            }),
        };
    }

    private static roleArn(accountId: string, roleName: string) {
        return "arn:aws:iam::" + accountId + ":role/" + roleName;
    }

    private static async getAwsAccounts(managementAwsAccountId: string) {
        const accounts: AwsAccount[] = [
            {
                name: "management",
                id: managementAwsAccountId,
                isManagement: true,
            }
        ];

        const organization = await aws.organizations.getOrganization();

        for (const account of organization.nonMasterAccounts) {
            if (account.status === "ACTIVE") {
                accounts.push({
                    name: account.name,
                    id: account.id,
                    resourceCreationRoleArn: Infrastructure.roleArn(account.id, "OrganizationAccountAccessRole"),
                    isManagement: false,
                });
            }
        }
        return accounts;
    }

    private static getManagementRoleName(functionName: string) {
        return functionName + "-management";
    }
}
