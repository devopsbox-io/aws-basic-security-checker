export const FORCE_MFA_GROUP = "MFARequired";

export async function sleep(ms: number) {
    return new Promise((resolve) => {
        setTimeout(resolve, ms);
    });
}

export function daysBeforeNow(date: Date) {
    const now = new Date();
    const differenceInTime = now.getTime() - date.getTime();
    return Math.floor(differenceInTime / (1000 * 3600 * 24));
}
