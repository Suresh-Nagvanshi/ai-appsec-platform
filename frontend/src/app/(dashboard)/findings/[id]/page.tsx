import { FindingDetails }
from "@/components/findings/finding-details";

export default async function FindingPage({
    params,
}:{
    params: Promise<{
        id:string
    }>
}){

    const { id } =
        await params;

    return (
        <FindingDetails
            id={id}
        />
    );

}