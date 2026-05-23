export async function getFindings() {

    await new Promise(
        (resolve)=>
            setTimeout(resolve,500)
    );

    return [
        {
            id:"1",
            title:"SQL Injection vulnerability",
            filePath:"src/api/users.ts",
            severity:"CRITICAL",
            riskScore:9.8,
            exploitability:"Very High",
            status:"OPEN"
        },

        {
            id:"2",
            title:"Hardcoded JWT secret",
            filePath:".env",
            severity:"HIGH",
            riskScore:8.1,
            exploitability:"High",
            status:"OPEN"
        },

        {
            id:"3",
            title:"Insecure deserialization",
            filePath:"serializers.py",
            severity:"MEDIUM",
            riskScore:6.5,
            exploitability:"Medium",
            status:"IN_PROGRESS"
        }
    ];

}