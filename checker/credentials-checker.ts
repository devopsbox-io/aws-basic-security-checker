import {CredentialReportRawUser, Iam} from "./aws/iam";
import {daysBeforeNow, FORCE_MFA_GROUP} from "../common/common";
import {Ses} from "./aws/ses";

export interface CredentialsCheckerArgs {
    adminEmail: string;
    awsAccountId: string;
    dryRun: boolean;
    iamRoleArn?: string;
    isManagementAccount: boolean;
}

const MFA_NOT_REQUIRED_TAG = "MFANotRequired";
const LOCK_ACCESS_KEY_EXPIRATION_TAG = "LockAccessKeyExpiration";
const EMAIL_TAG = "Email";
const WARNING_DAYS = 90;
const DISABLE_DAYS = 120;

export class CredentialsChecker {

    private readonly iam: Iam;
    private readonly ses: Ses;
    private readonly dryRun: boolean;

    static createDefault(args: CredentialsCheckerArgs) {
        return new CredentialsChecker(
            args,
            Iam.createDefault({
                iamRoleArn: args.iamRoleArn,
                dryRun: args.dryRun,
            }),
            Ses.createDefault(),
        );
    }

    constructor(readonly args: CredentialsCheckerArgs, iam: Iam, ses: Ses) {
        this.iam = iam;
        this.ses = ses;
        this.dryRun = args.dryRun;
    }

    async run() {
        const users = await this.iam.getUserDataFromCredentialReport();

        const allAdminNotifications: string[] = [];

        for (const rawUser of users) {
            const user = new CredentialReportUser(rawUser);

            if (user.isRoot) {
                const adminNotifications = await this.checkRootUser(user);
                allAdminNotifications.push(...adminNotifications);
            } else if (user.enabled) {
                const {
                    userNotifications,
                    adminNotifications,
                    email,
                } = await this.checkStandardUser(user);
                allAdminNotifications.push(...adminNotifications);

                if (email && userNotifications.length) {
                    const adminNotifications = await this.sendEmailToUser(user, email, userNotifications);
                    allAdminNotifications.push(...adminNotifications);
                }
            }
        }

        if (allAdminNotifications.length) {
            await this.sendEmailAdminEmail(this.args.adminEmail, allAdminNotifications);
        }
    }

    private async checkRootUser(user: CredentialReportUser) {
        const userChecker = new RootUserCredentialsChecker(this.args.isManagementAccount, this.iam, user);
        await userChecker.check();

        return userChecker.adminNotifications;
    }

    private async checkStandardUser(user: CredentialReportUser) {
        const userChecker = new StandardUserCredentialsChecker(this.iam, user, this.dryRun);
        await userChecker.check();

        return {
            userNotifications: userChecker.userNotifications,
            adminNotifications: userChecker.adminNotifications,
            email: userChecker.email,
        };
    }

    private async sendEmailToUser(user: CredentialReportUser, email: string, notifications: string[]) {
        const adminNotifications = [];

        const from = this.args.adminEmail;
        const to = email;
        const subject = `AWS credentials checker notification for account ${this.args.awsAccountId}`;
        const body = notifications.join("\n");

        try {
            await this.ses.sendEmail(from, to, subject, body);
        } catch (e) {
            if (e.name === "MessageRejected") {
                adminNotifications.push(`Message to ${user.name}(${email}) rejected!`);
            } else {
                throw e;
            }
        }

        return adminNotifications;
    }

    private async sendEmailAdminEmail(email: string, notifications: string[]) {
        const from = this.args.adminEmail;
        const to = this.args.adminEmail;
        const subject = `AWS credentials checker report for account ${this.args.awsAccountId}`;
        const body = notifications.join("\n");

        await this.ses.sendEmail(from, to, subject, body);
    }
}

class StandardUserCredentialsChecker {
    private readonly dryRunMessagePart: string;

    readonly userNotifications: string[] = [];
    readonly adminNotifications: string[] = [];

    email?: string;

    constructor(readonly iam: Iam, readonly user: CredentialReportUser, readonly dryRun: boolean) {
        this.dryRunMessagePart = dryRun ? "would be " : "";
    }

    async check() {
        const userTags = await this.iam.getUserTags(this.user.name);

        if (EMAIL_TAG in userTags) {
            this.email = userTags[EMAIL_TAG];
        } else {
            this.adminNotifications.push(`${this.user.name} does not have an "Email" tag.`);
        }

        await this.checkPassword();
        await this.checkMFA(userTags);
        await this.checkAccessKey(userTags, this.user.accessKey1Active, this.user.accessKey1LastRotated);
        await this.checkAccessKey(userTags, this.user.accessKey2Active, this.user.accessKey2LastRotated);
    }

    private async checkPassword() {
        if (this.user.passwordEnabled) {
            const passwordAge = daysBeforeNow(this.user.passwordLastChanged!);

            if (passwordAge > DISABLE_DAYS) {
                await this.iam.deleteLoginProfile(this.user.name);

                this.adminNotifications.push(`${this.user.name} login profile ${this.dryRunMessagePart}deleted.`);
            }
            if (passwordAge > WARNING_DAYS) {
                this.userNotifications.push(`${this.user.name} password is ${passwordAge} days old, please change it!`);
            }
        }
    }

    private async checkMFA(userTags: { [key: string]: string }) {
        if (this.user.passwordEnabled && !(MFA_NOT_REQUIRED_TAG in userTags && userTags[MFA_NOT_REQUIRED_TAG] === "true")) {
            const userGroups = await this.iam.getUserGroups(this.user.name);
            if (this.user.mfaActive) {
                if (userGroups.has(FORCE_MFA_GROUP)) {
                    await this.iam.removeUserFromGroup(this.user.name, FORCE_MFA_GROUP);

                    this.adminNotifications.push(`${this.user.name} ${this.dryRunMessagePart}removed from the ${FORCE_MFA_GROUP} group.`);
                }
            } else {
                if (!userGroups.has(FORCE_MFA_GROUP)) {
                    await this.iam.addUserToGroup(this.user.name, FORCE_MFA_GROUP);

                    this.adminNotifications.push(`${this.user.name} ${this.dryRunMessagePart}added to the ${FORCE_MFA_GROUP} group.`);
                    this.userNotifications.push(`${this.user.name} does not have multi-factor authentication (MFA) enabled, please enable it!`);
                }
            }
        }
    }

    async checkAccessKey(userTags: { [key: string]: string },
                         accessKeyActive: boolean,
                         accessKeyLastRotated?: Date) {
        if (!(LOCK_ACCESS_KEY_EXPIRATION_TAG in userTags && userTags[LOCK_ACCESS_KEY_EXPIRATION_TAG] === "true")) {
            if (accessKeyActive) {
                const accessKeyAge = daysBeforeNow(accessKeyLastRotated!);

                if (accessKeyAge > DISABLE_DAYS) {
                    const accessKeys = await this.iam.getAccessKeys(this.user.name);

                    for (const accessKey of accessKeys) {
                        const accessKeyAge = daysBeforeNow(accessKey.CreateDate!);

                        if (accessKeyAge > DISABLE_DAYS) {
                            await this.iam.disableAccessKey(this.user.name, accessKey.AccessKeyId!);

                            this.adminNotifications.push(`${this.user.name} access key ${accessKey.AccessKeyId} ${this.dryRunMessagePart}disabled.`);
                        }
                    }
                }
                if (accessKeyAge > WARNING_DAYS) {
                    this.userNotifications.push(`${this.user.name} access key is ${accessKeyAge} days old, please rotate it!`);
                }
            }
        }
    }
}

class RootUserCredentialsChecker {
    readonly adminNotifications: string[] = [];

    constructor(readonly isManagementAccount: boolean, readonly iam: Iam, readonly user: CredentialReportUser) {
    }

    async check() {
        await this.checkRootMFA();
        await this.checkAccessKey(this.user.accessKey1Active, this.user.accessKey1LastRotated);
        await this.checkAccessKey(this.user.accessKey2Active, this.user.accessKey2LastRotated);
    }

    private async checkRootMFA() {
        if (this.isManagementAccount && !this.user.mfaActive) {
            this.adminNotifications.push(`The root user does not have multi-factor authentication (MFA) enabled, please enable it!`);
        }
    }

    async checkAccessKey(accessKeyActive: boolean,
                         accessKeyLastRotated?: Date) {
        if (accessKeyActive) {
            const accessKeyAge = daysBeforeNow(accessKeyLastRotated!);

            if (accessKeyAge > WARNING_DAYS) {
                this.adminNotifications.push(`The root user"s access key is ${accessKeyAge} days old, please rotate it!`);
            }
        }
    }
}

class CredentialReportUser {
    get name(): string {
        return this.rawUser.user;
    }

    get arn(): string {
        return this.rawUser.arn;
    }

    get isRoot(): boolean {
        return this.rawUser.user === "<root_account>";
    }

    get passwordEnabled(): boolean {
        return this.rawUser.password_enabled === "true";
    }

    get passwordLastChanged(): Date | undefined {
        const passwordLastChanged = this.rawUser.password_last_changed;
        if (passwordLastChanged === "not_supported" || passwordLastChanged === "N/A") {
            return undefined;
        } else {
            return new Date(passwordLastChanged);
        }
    }

    get mfaActive(): boolean {
        return this.rawUser.mfa_active === "true";
    }

    get accessKey1Active(): boolean {
        return this.rawUser.access_key_1_active === "true";
    }

    get accessKey1LastRotated(): Date | undefined {
        const accessKey1LastRotated = this.rawUser.access_key_1_last_rotated;
        if (accessKey1LastRotated === "N/A") {
            return undefined;
        } else {
            return new Date(accessKey1LastRotated);
        }
    }

    get accessKey2Active(): boolean {
        return this.rawUser.access_key_2_active === "true";
    }

    get accessKey2LastRotated(): Date | undefined {
        const accessKey2LastRotated = this.rawUser.access_key_2_last_rotated;
        if (accessKey2LastRotated === "N/A") {
            return undefined;
        } else {
            return new Date(accessKey2LastRotated);
        }
    }

    get enabled(): boolean {
        return this.passwordEnabled || this.accessKey1Active || this.accessKey2Active;
    }

    constructor(private rawUser: CredentialReportRawUser) {
    }
}
