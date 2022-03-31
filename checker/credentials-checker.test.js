import {CredentialsChecker} from "./credentials-checker";

const checker = require("./credentials-checker");

describe("Credential Checker", () => {
    jest.useFakeTimers()
        .setSystemTime(new Date("2021-10-21T03:32:20+00:00").getTime());
    const iamMock = {
        getUserDataFromCredentialReport: jest.fn(),
        getUserTags: jest.fn(),
        getUserGroups: jest.fn(),
        getAccessKeys: jest.fn(),
        removeUserFromGroup: jest.fn(),
        addUserToGroup: jest.fn(),
        deleteLoginProfile: jest.fn(),
        disableAccessKey: jest.fn(),
    };
    const sesMock = {
        sendEmail: jest.fn(),
    };

    describe("management account", () => {
        const credentialsChecker = new CredentialsChecker(
            {
                isManagementAccount: true,
                awsAccountId: "111111111111",
                iamRoleArn: "",
                adminEmail: "admin@tmp.org",
                dryRun: false,
            },
            iamMock,
            sesMock,
        );

        it("should send root inactive MFA email", async () => {
            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "<root_account>",
                    arn: "arn:aws:iam::111111111111:root",
                    password_enabled: "not_supported",
                    password_last_changed: "not_supported",
                    mfa_active: "false",
                    access_key_1_active: "false",
                    access_key_1_last_rotated: "N/A",
                    access_key_2_active: "false",
                    access_key_2_last_rotated: "N/A",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "admin@tmp.org",
                "AWS credentials checker report for account 111111111111",
                "The root user does not have multi-factor authentication (MFA) enabled, please enable it!",
            );
        });

        it("should send root old access key email", async () => {
            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "<root_account>",
                    arn: "arn:aws:iam::111111111111:root",
                    password_enabled: "not_supported",
                    password_last_changed: "not_supported",
                    mfa_active: "true",
                    access_key_1_active: "true",
                    access_key_1_last_rotated: "2021-06-28T03:32:20+00:00",
                    access_key_2_active: "false",
                    access_key_2_last_rotated: "N/A",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "admin@tmp.org",
                "AWS credentials checker report for account 111111111111",
                "The root user\"s access key is 115 days old, please rotate it!",
            );
        });

        it("should send user inactive MFA email and add to the MFARequired group", async () => {
            iamMock.getUserTags.mockReturnValue({
                "Email": "user1@tmp.org",
            });
            iamMock.getUserGroups.mockReturnValue(new Set());

            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "user1",
                    arn: "arn:aws:iam::111111111111:user/user1",
                    password_enabled: "true",
                    password_last_changed: "2021-10-20T03:32:20+00:00",
                    mfa_active: "false",
                    access_key_1_active: "false",
                    access_key_1_last_rotated: "N/A",
                    access_key_2_active: "false",
                    access_key_2_last_rotated: "N/A",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "admin@tmp.org",
                "AWS credentials checker report for account 111111111111",
                "user1 added to the MFARequired group.",
            );
            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "user1@tmp.org",
                "AWS credentials checker notification for account 111111111111",
                "user1 does not have multi-factor authentication (MFA) enabled, please enable it!",
            );

            expect(iamMock.removeUserFromGroup).not.toHaveBeenCalled();
            expect(iamMock.addUserToGroup).toHaveBeenCalledWith("user1", "MFARequired");
            expect(iamMock.deleteLoginProfile).not.toHaveBeenCalled();
            expect(iamMock.disableAccessKey).not.toHaveBeenCalled();
        });

        it("should not send user inactive MFA email nor add to the MFARequired group when MFANotRequired is set to true", async () => {
            iamMock.getUserTags.mockReturnValue({
                "Email": "user1@tmp.org",
                "MFANotRequired": "true",
            });
            iamMock.getUserGroups.mockReturnValue(new Set());

            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "user1",
                    arn: "arn:aws:iam::111111111111:user/user1",
                    password_enabled: "true",
                    password_last_changed: "2021-10-20T03:32:20+00:00",
                    mfa_active: "false",
                    access_key_1_active: "false",
                    access_key_1_last_rotated: "N/A",
                    access_key_2_active: "false",
                    access_key_2_last_rotated: "N/A",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).not.toHaveBeenCalled();

            expect(iamMock.removeUserFromGroup).not.toHaveBeenCalled();
            expect(iamMock.addUserToGroup).not.toHaveBeenCalled();
            expect(iamMock.deleteLoginProfile).not.toHaveBeenCalled();
            expect(iamMock.disableAccessKey).not.toHaveBeenCalled();
        });

        it("should remove user from the MFARequired group when MFA enabled", async () => {
            iamMock.getUserTags.mockReturnValue({
                "Email": "user1@tmp.org",
            });
            iamMock.getUserGroups.mockReturnValue(new Set(["MFARequired"]));

            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "user1",
                    arn: "arn:aws:iam::111111111111:user/user1",
                    password_enabled: "true",
                    password_last_changed: "2021-10-20T03:32:20+00:00",
                    mfa_active: "true",
                    access_key_1_active: "false",
                    access_key_1_last_rotated: "N/A",
                    access_key_2_active: "false",
                    access_key_2_last_rotated: "N/A",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "admin@tmp.org",
                "AWS credentials checker report for account 111111111111",
                "user1 removed from the MFARequired group.",
            );

            expect(iamMock.removeUserFromGroup).toHaveBeenCalledWith("user1", "MFARequired");
            expect(iamMock.addUserToGroup).not.toHaveBeenCalled();
            expect(iamMock.deleteLoginProfile).not.toHaveBeenCalled();
            expect(iamMock.disableAccessKey).not.toHaveBeenCalled();
        });

        it("should send user old access key email", async () => {
            iamMock.getUserTags.mockReturnValue({
                "Email": "user1@tmp.org",
            });
            iamMock.getUserGroups.mockReturnValue(new Set());

            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "user1",
                    arn: "arn:aws:iam::111111111111:user/user1",
                    password_enabled: "true",
                    password_last_changed: "2021-10-20T03:32:20+00:00",
                    mfa_active: "true",
                    access_key_1_active: "true",
                    access_key_1_last_rotated: "2021-07-10T03:32:20+00:00",
                    access_key_2_active: "false",
                    access_key_2_last_rotated: "N/A",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "user1@tmp.org",
                "AWS credentials checker notification for account 111111111111",
                "user1 access key is 103 days old, please rotate it!",
            );

            expect(iamMock.removeUserFromGroup).not.toHaveBeenCalled();
            expect(iamMock.addUserToGroup).not.toHaveBeenCalled();
            expect(iamMock.deleteLoginProfile).not.toHaveBeenCalled();
            expect(iamMock.disableAccessKey).not.toHaveBeenCalled();
        });

        it("should send user old access key email and disable the access key", async () => {
            iamMock.getUserTags.mockReturnValue({
                "Email": "user1@tmp.org",
            });
            iamMock.getUserGroups.mockReturnValue(new Set());
            iamMock.getAccessKeys.mockReturnValue([
                {
                    CreateDate: new Date("2021-06-10T03:32:20+00:00"),
                    AccessKeyId: "accessKeyId1",
                },
                {
                    CreateDate: new Date("2021-06-10T03:32:20+00:00"),
                    AccessKeyId: "accessKeyId2",
                },
            ]);

            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "user1",
                    arn: "arn:aws:iam::111111111111:user/user1",
                    password_enabled: "true",
                    password_last_changed: "2021-10-20T03:32:20+00:00",
                    mfa_active: "true",
                    access_key_1_active: "true",
                    access_key_1_last_rotated: "2021-06-10T03:32:20+00:00",
                    access_key_2_active: "true",
                    access_key_2_last_rotated: "2021-06-10T03:32:20+00:00",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "user1@tmp.org",
                "AWS credentials checker notification for account 111111111111",
                "user1 access key is 133 days old, please rotate it!\nuser1 access key is 133 days old, please rotate it!",
            );
            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "admin@tmp.org",
                "AWS credentials checker report for account 111111111111",
                "user1 access key accessKeyId1 disabled.\n" +
                "user1 access key accessKeyId2 disabled.\n" +
                "user1 access key accessKeyId1 disabled.\n" +
                "user1 access key accessKeyId2 disabled.",
            );

            expect(iamMock.removeUserFromGroup).not.toHaveBeenCalled();
            expect(iamMock.addUserToGroup).not.toHaveBeenCalled();
            expect(iamMock.deleteLoginProfile).not.toHaveBeenCalled();
            expect(iamMock.disableAccessKey).toHaveBeenCalledWith("user1", "accessKeyId1");
            expect(iamMock.disableAccessKey).toHaveBeenCalledWith("user1", "accessKeyId2");
        });

        it("should not send user old access key email nor disable the access key when user has the LockAccessKeyExpiration tag set to true", async () => {
            iamMock.getUserTags.mockReturnValue({
                "Email": "user1@tmp.org",
                "LockAccessKeyExpiration": "true",
            });
            iamMock.getUserGroups.mockReturnValue(new Set());

            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "user1",
                    arn: "arn:aws:iam::111111111111:user/user1",
                    password_enabled: "true",
                    password_last_changed: "2021-10-20T03:32:20+00:00",
                    mfa_active: "true",
                    access_key_1_active: "true",
                    access_key_1_last_rotated: "2021-06-10T03:32:20+00:00",
                    access_key_2_active: "true",
                    access_key_2_last_rotated: "2021-06-10T03:32:20+00:00",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).not.toHaveBeenCalled();
            expect(iamMock.removeUserFromGroup).not.toHaveBeenCalled();
            expect(iamMock.addUserToGroup).not.toHaveBeenCalled();
            expect(iamMock.deleteLoginProfile).not.toHaveBeenCalled();
            expect(iamMock.disableAccessKey).not.toHaveBeenCalled();
        });

        it("should send user old password email", async () => {
            iamMock.getUserTags.mockReturnValue({
                "Email": "user1@tmp.org",
            });
            iamMock.getUserGroups.mockReturnValue(new Set());

            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "user1",
                    arn: "arn:aws:iam::111111111111:user/user1",
                    password_enabled: "true",
                    password_last_changed: "2021-07-20T03:32:20+00:00",
                    mfa_active: "true",
                    access_key_1_active: "false",
                    access_key_1_last_rotated: "N/A",
                    access_key_2_active: "false",
                    access_key_2_last_rotated: "N/A",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "user1@tmp.org",
                "AWS credentials checker notification for account 111111111111",
                "user1 password is 93 days old, please change it!",
            );

            expect(iamMock.removeUserFromGroup).not.toHaveBeenCalled();
            expect(iamMock.addUserToGroup).not.toHaveBeenCalled();
            expect(iamMock.deleteLoginProfile).not.toHaveBeenCalled();
            expect(iamMock.disableAccessKey).not.toHaveBeenCalled();
        });

        it("should send user old password email and disable login profile", async () => {
            iamMock.getUserTags.mockReturnValue({
                "Email": "user1@tmp.org",
            });
            iamMock.getUserGroups.mockReturnValue(new Set());

            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "user1",
                    arn: "arn:aws:iam::111111111111:user/user1",
                    password_enabled: "true",
                    password_last_changed: "2021-06-20T03:32:20+00:00",
                    mfa_active: "true",
                    access_key_1_active: "false",
                    access_key_1_last_rotated: "N/A",
                    access_key_2_active: "false",
                    access_key_2_last_rotated: "N/A",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "user1@tmp.org",
                "AWS credentials checker notification for account 111111111111",
                "user1 password is 123 days old, please change it!",
            );
            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "admin@tmp.org",
                "AWS credentials checker report for account 111111111111",
                "user1 login profile deleted.",
            );

            expect(iamMock.removeUserFromGroup).not.toHaveBeenCalled();
            expect(iamMock.addUserToGroup).not.toHaveBeenCalled();
            expect(iamMock.deleteLoginProfile).toHaveBeenCalledWith("user1");
            expect(iamMock.disableAccessKey).not.toHaveBeenCalled();
        });

        it("should notify admin when user does not have an Email tag", async () => {
            iamMock.getUserTags.mockReturnValue({});
            iamMock.getUserGroups.mockReturnValue(new Set());

            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "user1",
                    arn: "arn:aws:iam::111111111111:user/user1",
                    password_enabled: "true",
                    password_last_changed: "2021-07-20T03:32:20+00:00",
                    mfa_active: "true",
                    access_key_1_active: "false",
                    access_key_1_last_rotated: "N/A",
                    access_key_2_active: "false",
                    access_key_2_last_rotated: "N/A",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "admin@tmp.org",
                "AWS credentials checker report for account 111111111111",
                "user1 does not have an \"Email\" tag.",
            );

            expect(iamMock.removeUserFromGroup).not.toHaveBeenCalled();
            expect(iamMock.addUserToGroup).not.toHaveBeenCalled();
            expect(iamMock.deleteLoginProfile).not.toHaveBeenCalled();
            expect(iamMock.disableAccessKey).not.toHaveBeenCalled();
        });

        it("should notify admin when send email throws MessageRejected", async () => {
            iamMock.getUserTags.mockReturnValue({
                "Email": "user1@tmp.org",
            });
            iamMock.getUserGroups.mockReturnValue(new Set());
            sesMock.sendEmail.mockImplementation((from, to, subject, body) => {
                if (to === "user1@tmp.org") {
                    const error = new Error();
                    error.name = "MessageRejected";
                    throw error;
                }
            });

            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "user1",
                    arn: "arn:aws:iam::111111111111:user/user1",
                    password_enabled: "true",
                    password_last_changed: "2021-07-20T03:32:20+00:00",
                    mfa_active: "true",
                    access_key_1_active: "false",
                    access_key_1_last_rotated: "N/A",
                    access_key_2_active: "false",
                    access_key_2_last_rotated: "N/A",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "admin@tmp.org",
                "AWS credentials checker report for account 111111111111",
                "Message to user1(user1@tmp.org) rejected!",
            );

            expect(iamMock.removeUserFromGroup).not.toHaveBeenCalled();
            expect(iamMock.addUserToGroup).not.toHaveBeenCalled();
            expect(iamMock.deleteLoginProfile).not.toHaveBeenCalled();
            expect(iamMock.disableAccessKey).not.toHaveBeenCalled();
        });
    });


    describe("non management account", () => {
        const credentialsChecker = new CredentialsChecker(
            {
                isManagementAccount: false,
                awsAccountId: "222222222222",
                iamRoleArn: "fakeArn",
                adminEmail: "admin@tmp.org",
                dryRun: false,
            },
            iamMock,
            sesMock,
        );

        it("should not send root inactive MFA email", async () => {
            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "<root_account>",
                    arn: "arn:aws:iam::222222222222:root",
                    password_enabled: "not_supported",
                    password_last_changed: "not_supported",
                    mfa_active: "false",
                    access_key_1_active: "false",
                    access_key_1_last_rotated: "N/A",
                    access_key_2_active: "false",
                    access_key_2_last_rotated: "N/A",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).not.toHaveBeenCalled();
        });
    });

    describe("dry run", () => {
        const credentialsChecker = new CredentialsChecker(
            {
                isManagementAccount: true,
                awsAccountId: "111111111111",
                iamRoleArn: "",
                adminEmail: "admin@tmp.org",
                dryRun: true,
            },
            iamMock,
            sesMock,
        );

        it("should send dry run notification about adding to the MFARequired group", async () => {
            iamMock.getUserTags.mockReturnValue({
                "Email": "user1@tmp.org",
            });
            iamMock.getUserGroups.mockReturnValue(new Set());

            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "user1",
                    arn: "arn:aws:iam::111111111111:user/user1",
                    password_enabled: "true",
                    password_last_changed: "2021-10-20T03:32:20+00:00",
                    mfa_active: "false",
                    access_key_1_active: "false",
                    access_key_1_last_rotated: "N/A",
                    access_key_2_active: "false",
                    access_key_2_last_rotated: "N/A",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "admin@tmp.org",
                "AWS credentials checker report for account 111111111111",
                "user1 would be added to the MFARequired group.",
            );
        });

        it("should send dry run notification about removing user from the MFARequired", async () => {
            iamMock.getUserTags.mockReturnValue({
                "Email": "user1@tmp.org",
            });
            iamMock.getUserGroups.mockReturnValue(new Set(["MFARequired"]));

            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "user1",
                    arn: "arn:aws:iam::111111111111:user/user1",
                    password_enabled: "true",
                    password_last_changed: "2021-10-20T03:32:20+00:00",
                    mfa_active: "true",
                    access_key_1_active: "false",
                    access_key_1_last_rotated: "N/A",
                    access_key_2_active: "false",
                    access_key_2_last_rotated: "N/A",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "admin@tmp.org",
                "AWS credentials checker report for account 111111111111",
                "user1 would be removed from the MFARequired group.",
            );
        });

        it("should send dry run notification about disabling access keys", async () => {
            iamMock.getUserTags.mockReturnValue({
                "Email": "user1@tmp.org",
            });
            iamMock.getUserGroups.mockReturnValue(new Set());
            iamMock.getAccessKeys.mockReturnValue([
                {
                    CreateDate: new Date("2021-06-10T03:32:20+00:00"),
                    AccessKeyId: "accessKeyId1",
                },
                {
                    CreateDate: new Date("2021-06-10T03:32:20+00:00"),
                    AccessKeyId: "accessKeyId2",
                },
            ]);

            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "user1",
                    arn: "arn:aws:iam::111111111111:user/user1",
                    password_enabled: "true",
                    password_last_changed: "2021-10-20T03:32:20+00:00",
                    mfa_active: "true",
                    access_key_1_active: "true",
                    access_key_1_last_rotated: "2021-06-10T03:32:20+00:00",
                    access_key_2_active: "true",
                    access_key_2_last_rotated: "2021-06-10T03:32:20+00:00",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "admin@tmp.org",
                "AWS credentials checker report for account 111111111111",
                "user1 access key accessKeyId1 would be disabled.\n" +
                "user1 access key accessKeyId2 would be disabled.\n" +
                "user1 access key accessKeyId1 would be disabled.\n" +
                "user1 access key accessKeyId2 would be disabled.",
            );
        });

        it("should send dry run notification about disabling login profile", async () => {
            iamMock.getUserTags.mockReturnValue({
                "Email": "user1@tmp.org",
            });
            iamMock.getUserGroups.mockReturnValue(new Set());

            iamMock.getUserDataFromCredentialReport.mockReturnValue([
                {
                    user: "user1",
                    arn: "arn:aws:iam::111111111111:user/user1",
                    password_enabled: "true",
                    password_last_changed: "2021-06-20T03:32:20+00:00",
                    mfa_active: "true",
                    access_key_1_active: "false",
                    access_key_1_last_rotated: "N/A",
                    access_key_2_active: "false",
                    access_key_2_last_rotated: "N/A",
                },
            ]);

            await credentialsChecker.run();

            expect(sesMock.sendEmail).toHaveBeenCalledWith(
                "admin@tmp.org",
                "admin@tmp.org",
                "AWS credentials checker report for account 111111111111",
                "user1 login profile would be deleted.",
            );
        });
    });
});
