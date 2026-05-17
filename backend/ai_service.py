from langchain_groq import ChatGroq
from dotenv import load_dotenv
import os

# Load .env
load_dotenv()

# Initialize Groq LLM
llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    temperature=0
)

def analyze_vulnerability(vulnerability_data):
    prompt = f"""
    You are an expert Application Security engineer.

    Analyze this vulnerability finding and provide:

        1. Vulnerability summary
        2. Why it is dangerous
        3. Real-world impact
        4. Severity explanation
        5. Secure fix recommendation
        6. MITRE ATT&CK relevance
        7. OWASP relevance

        Vulnerability Data:
            {vulnerability_data}

        Return concise but professional output.
    """

    response = llm.invoke(prompt)
    return response.content