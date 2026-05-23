export type RepositoryProvider =
    | "GitHub"
    | "GitLab"
    | "Bitbucket";

export interface Repository {

    id: string;

    name: string;

    provider: RepositoryProvider;

    status:
        | "CONNECTED"
        | "DISCONNECTED";

    url: string;

    lastScan?: string;

}

const repositories: Repository[] = [

    {

        id: "1",

        name: "WebGoat",

        provider: "GitHub",

        status: "CONNECTED",

        url:
            "https://github.com/WebGoat/WebGoat",

        lastScan:
            "5 mins ago"

    },

    {

        id: "2",

        name: "Varsity_Vibe",

        provider: "GitHub",

        status: "CONNECTED",

        url:
            "https://github.com/user/Varsity_Vibe",

        lastScan:
            "15 mins ago"

    },

    {

        id: "3",

        name: "AdreliaERP",

        provider: "GitHub",

        status: "CONNECTED",

        url:
            "https://github.com/company/AdreliaERP",

        lastScan:
            "1 hour ago"

    }

];

export async function getRepositories() {

    await new Promise(
        (resolve)=>
            setTimeout(resolve,500)
    );

    return repositories;

}

export async function addRepository(

    repository: Omit<
        Repository,
        "id"
    >

) {

    await new Promise(
        (resolve)=>
            setTimeout(resolve,500)
    );

    const newRepository = {

        ...repository,

        id:
            crypto.randomUUID()

    };

    repositories.unshift(
        newRepository
    );

    return newRepository;

}