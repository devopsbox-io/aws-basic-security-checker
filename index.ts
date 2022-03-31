import {Infrastructure} from "./infrastructure/infrastructure";

const run = async () => {
    const infrastructure = new Infrastructure();
    return await infrastructure.create();
}

export = run().catch(err => {
    console.log(err);
    process.exit(1);
});
