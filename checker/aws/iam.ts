import {
    AccessKeyMetadata,
    AddUserToGroupCommand,
    DeleteLoginProfileCommand,
    GenerateCredentialReportCommand,
    GetCredentialReportCommand,
    GetCredentialReportCommandOutput,
    IAMClient,
    IAMClientConfig,
    paginateListAccessKeys,
    paginateListGroupsForUser,
    paginateListUserTags,
    RemoveUserFromGroupCommand,
    UpdateAccessKeyCommand
} from "@aws-sdk/client-iam";
import {sleep} from "../../common/common";
import {fromTemporaryCredentials} from "@aws-sdk/credential-providers";

export interface IamArgs {
    iamRoleArn?: string;
    dryRun: boolean;
}

export class Iam {
    private readonly iam: IAMClient;

    static createDefault(args: IamArgs) {
        return new Iam(
            args,
            Iam.createIamClient(args),
        );
    }

    constructor(readonly args: IamArgs, iam: IAMClient) {
        this.iam = iam;
    }

    private static createIamClient(args: IamArgs) {
        const iamClientConfig: IAMClientConfig = {};
        if (args.iamRoleArn) {
            iamClientConfig.credentials = fromTemporaryCredentials({
                params: {
                    RoleArn: args.iamRoleArn,
                }
            });
        }
        return new IAMClient(iamClientConfig);
    }

    async getUserTags(userName: string): Promise<{ [key: string]: string }> {
        const result: { [key: string]: string } = {}

        const paginator = paginateListUserTags({
            client: this.iam,
        }, {
            UserName: userName,
        });

        for await (const page of paginator) {
            for (const tag of page.Tags!) {
                result[tag.Key!] = tag.Value!;
            }
        }

        return result;
    }

    async getUserGroups(userName: string): Promise<Set<string>> {
        const result: Set<string> = new Set<string>();

        const paginator = paginateListGroupsForUser({
            client: this.iam,
        }, {
            UserName: userName,
        });

        for await (const page of paginator) {
            for (const group of page.Groups!) {
                result.add(group.GroupName!);
            }
        }

        return result;
    }

    async getAccessKeys(userName: string) {
        const result: AccessKeyMetadata[] = [];

        const paginator = paginateListAccessKeys(
            {
                client: this.iam,
            },
            {
                UserName: userName,
            },
        );

        for await (const page of paginator) {
            for (const keyMetadata of page.AccessKeyMetadata!) {
                result.push(keyMetadata);
            }
        }
        return result;
    }

    async removeUserFromGroup(userName: string, groupName: string) {
        if (this.args.dryRun) {
            console.log("Should remove " + userName + " from group " + groupName);
        } else {
            console.log("Removing " + userName + " from group " + groupName);
            await this.iam.send(new RemoveUserFromGroupCommand({
                UserName: userName,
                GroupName: groupName,
            }));
        }
    }

    async addUserToGroup(userName: string, groupName: string) {
        if (this.args.dryRun) {
            console.log("Should add " + userName + " to group " + groupName);
        } else {
            console.log("Adding " + userName + " to group " + groupName);
            await this.iam.send(new AddUserToGroupCommand({
                UserName: userName,
                GroupName: groupName,
            }));
        }
    }

    async deleteLoginProfile(userName: string) {
        if (this.args.dryRun) {
            console.log("Should delete login profile for user " + userName);
        } else {
            console.log("Deleting login profile for user " + userName);
            await this.iam.send(new DeleteLoginProfileCommand({
                UserName: userName,
            }));
        }
    }

    async disableAccessKey(userName: string, accessKeyId: string) {
        if (this.args.dryRun) {
            console.log("Should disable access key " + accessKeyId + " for user " + userName);
        } else {
            console.log("Disabling access key " + accessKeyId + " for user " + userName);
            await this.iam.send(new UpdateAccessKeyCommand({
                UserName: userName,
                AccessKeyId: accessKeyId,
                Status: "Inactive",
            }));
        }
    }

    async getUserDataFromCredentialReport() {
        const startDate = new Date();
        const startTime = startDate.getTime();
        const startMinus4HoursDate = new Date(startDate);
        startMinus4HoursDate.setHours(startDate.getHours() - 4);
        const startMinus4HoursTime = startMinus4HoursDate.getTime();

        let shouldGenerate = false;

        let getCredentialReportOutput: GetCredentialReportCommandOutput;
        try {
            getCredentialReportOutput = await this.iam.send(new GetCredentialReportCommand({}));

            const reportGeneratedTime = getCredentialReportOutput.GeneratedTime?.getTime()!;

            if (reportGeneratedTime < startMinus4HoursTime) {
                shouldGenerate = true;
            }
        } catch (e) {
            if (e.name === "ReportNotPresent") {
                shouldGenerate = true;
            } else {
                throw e;
            }
        }

        if (shouldGenerate) {
            await this.iam.send(new GenerateCredentialReportCommand({}));

            let shouldGetAgain = true;

            while (shouldGetAgain) {
                shouldGetAgain = false;

                try {
                    getCredentialReportOutput = await this.iam.send(new GetCredentialReportCommand({}));
                } catch (e) {
                    if (e.name === "ReportInProgress") {
                        shouldGetAgain = true;
                        await sleep(1000);
                    } else {
                        throw e;
                    }
                }

                if (!shouldGetAgain) {
                    const reportGeneratedTime = getCredentialReportOutput!.GeneratedTime?.getTime()!;

                    if (reportGeneratedTime < startTime) {
                        shouldGetAgain = true;
                        await sleep(1000);
                    }
                }
            }
        }


        const buffer = Buffer.from(getCredentialReportOutput!.Content!);

        return Iam.readCredentialReportCsv(buffer.toString());
    }

    private static readCredentialReportCsv(csv: string): CredentialReportRawUser[] {
        const lines = csv.split("\n");

        const result: CredentialReportRawUser[] = [];
        const headers = lines[0].split(",");

        for (let i = 1; i < lines.length; i++) {
            const obj: any = {};
            const currentLine = lines[i].split(",");

            for (let j = 0; j < headers.length; j++) {
                obj[headers[j]] = currentLine[j];
            }

            result.push(obj);
        }
        return result;
    }
}

export interface CredentialReportRawUser {
    user: string;
    arn: string;
    user_creation_time: string;
    password_enabled: string;
    password_last_used: string;
    password_last_changed: string;
    password_next_rotation: string;
    mfa_active: string;
    access_key_1_active: string;
    access_key_1_last_rotated: string;
    access_key_1_last_used_date: string;
    access_key_1_last_used_region: string;
    access_key_1_last_used_service: string;
    access_key_2_active: string;
    access_key_2_last_rotated: string;
    access_key_2_last_used_date: string;
    access_key_2_last_used_region: string;
    access_key_2_last_used_service: string;
    cert_1_active: string;
    cert_1_last_rotated: string;
    cert_2_active: string;
    cert_2_last_rotated: string;
}
