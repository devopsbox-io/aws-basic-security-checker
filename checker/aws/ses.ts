import {SendEmailCommand, SESClient} from "@aws-sdk/client-ses";

export class Ses {
    private readonly ses: SESClient;

    static createDefault() {
        return new Ses(
            new SESClient({}),
        );
    }

    constructor(ses: SESClient) {
        this.ses = ses || new SESClient({});
    }

    async sendEmail(from: string, to: string, subject: string, body: string) {
        await this.ses.send(new SendEmailCommand({
            Source: from,
            Destination: {
                ToAddresses: [to],
            },
            Message: {
                Subject: {
                    Data: subject,
                },
                Body: {
                    Text: {
                        Data: body,
                    },
                }
            }
        }));
    }
}
